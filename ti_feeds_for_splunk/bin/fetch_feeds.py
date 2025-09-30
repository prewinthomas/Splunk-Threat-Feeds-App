#!/usr/bin/env python3
"""
fetch_feeds.py
Splunk scripted input to fetch open-source threat feeds, normalize them,
and emit only NEW IOCs (no duplicates) using KV Store state tracking.
"""

import os, sys, time, json, csv, io, urllib.request, logging, re, ssl
from splunklib.client import Service

# --- Logging setup ---
SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "C:\\Program Files\\Splunk")
LOG_FILE = os.path.join(SPLUNK_HOME, "var", "log", "splunk", "ti_feeds.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("ti_feeds")

NOW = int(time.time())

# --- Helpers ---
def emit(event: dict):
    """Write a JSON event to stdout for Splunk ingestion."""
    sys.stdout.write(json.dumps(event) + "\n")

def fetch_url(url: str) -> str:
    """Fetch a URL and return its decoded text, logging size."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "splunk-ti-openfeeds/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
        logger.info("Fetched %s (%d bytes)", url, len(data))
        return data
    except Exception as e:
        logger.error("Failed to fetch %s: %s", url, e)
        return ""

def connect_kvstore(session_key):
    """Connect to the Splunk KV Store collection for deduplication."""
    try:
        service = Service(token=session_key, app="ti_feeds_for_splunk")
        collection = service.kvstore["ti_feed_state"]
        logger.info("Connected to KV Store collection ti_feed_state")
        return collection
    except Exception as e:
        logger.exception("Failed to connect to KV Store: %s", e)
        sys.exit(1)

def load_seen_keys(collection):
    """Load all previously seen keys from KV Store."""
    try:
        all_docs = collection.data.query()
        seen = {doc["_key"] for doc in all_docs}
        logger.info("Loaded %d existing keys from KV Store", len(seen))
        return seen
    except Exception as e:
        logger.warning("Failed to load seen keys: %s", e)
        return set()

def bulk_mark_seen(session_key, app, collection, new_keys, chunk_size=500):
    """Bulk insert new keys into KV Store in chunks."""
    if not new_keys:
        return
    url = f"https://localhost:8089/servicesNS/nobody/{app}/storage/collections/data/{collection}/batch_save?insert_only=true"
    headers = {
        "Authorization": f"Splunk {session_key}",
        "Content-Type": "application/json"
    }
    for i in range(0, len(new_keys), chunk_size):
        batch = new_keys[i:i+chunk_size]
        body = json.dumps([{"_key": k} for k in batch]).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, context=ssl._create_unverified_context()):
                logger.info("Bulk inserted %d keys into KV Store", len(batch))
        except Exception as e:
            logger.error("Bulk insert failed for batch starting at %d: %s", i, e)

def process_ioc(seen, new_keys, value, ioc_type, feed, counters, **kwargs):
    """Emit a new IOC event if not already seen, track in KV Store and counters."""
    key = f"{feed}:{kwargs.get('_id', value)}"
    if key not in seen:
        event = {
            "value": value,
            "type": ioc_type,
            "feed": feed,
            "_time": NOW
        }
        if "_id" in kwargs:
            kwargs.pop("_id")
        event.update(kwargs)
        emit(event)
        new_keys.append(key)
        seen.add(key)
        counters[feed] = counters.get(feed, 0) + 1

# --- IOC type detection ---
def detect_ioc_type(ioc: str) -> str:
    """Guess IOC type based on format."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if "/" in ioc and re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", ioc):
        return "ip"
    if ioc.lower().startswith(("http://", "https://")):
        return "url"
    if re.match(r"^[0-9a-f]{32}$", ioc, re.I):
        return "hash"
    if re.match(r"^[0-9a-f]{40}$", ioc, re.I):
        return "hash"
    if re.match(r"^[0-9a-f]{64}$", ioc, re.I):
        return "hash"
    if "." in ioc:
        return "domain"
    return "ioc"
# --- Feed collectors ---
def collect_feodo(seen, new_keys, counters):
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    data = fetch_url(url)
    if not data:
        logger.error("Feodo feed returned no data")
        return
    buf = io.StringIO("\n".join([l for l in data.splitlines() if not l.startswith("#")]))
    reader = csv.DictReader(buf)
    for row in reader:
        ip = row.get("dst_ip")
        if not ip:
            continue
        process_ioc(
            seen, new_keys, ip, "ip", "feodo", counters,
            first_seen=row.get("first_seen_utc"),
            last_seen=row.get("last_online"),
            dst_port=row.get("dst_port"),
            c2_status=row.get("c2_status"),
            malware=row.get("malware"),
            severity="high"
        )

def collect_spamhaus(seen, new_keys, counters):
    url = "https://www.spamhaus.org/drop/drop.txt"
    data = fetch_url(url)
    if not data:
        logger.error("Spamhaus feed returned no data")
        return
    for line in data.splitlines():
        if not line or line.startswith(";"):
            continue
        parts = line.split(";")
        cidr = parts[0].strip()
        desc = parts[1].strip() if len(parts) > 1 else ""
        process_ioc(seen, new_keys, cidr, "ip", "spamhaus_drop", counters,
                    description=desc, severity="high")

def collect_openphish(seen, new_keys, counters):
    url = "https://openphish.com/feed.txt"
    data = fetch_url(url)
    if not data:
        logger.error("OpenPhish feed returned no data")
        return
    for line in data.splitlines():
        url_val = line.strip()
        if not url_val or url_val.startswith("#"):
            continue
        process_ioc(seen, new_keys, url_val, "url", "openphish", counters, severity="high")

def collect_threatfox(seen, new_keys, counters):
    url = "https://threatfox.abuse.ch/export/csv/recent/"
    data = fetch_url(url)
    if not data:
        logger.error("ThreatFox feed returned no data")
        return

    # Remove only comment lines, keep header + data
    lines = []
    for line in data.splitlines():
        if line.startswith("#"):
            continue
        lines.append(line)
    buf = io.StringIO("\n".join(lines))

    # Explicit fieldnames for ThreatFox
    fieldnames = [
        "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type",
        "fk_malware","malware_alias","malware_printable","last_seen_utc",
        "confidence_level","reference","tags","anonymous","reporter"
    ]
    reader = csv.DictReader(buf, fieldnames=fieldnames, skipinitialspace=True)
    next(reader, None)  # skip the header row

    for idx, row in enumerate(reader):
        if idx < 5:  # log first 5 rows for inspection
            logger.info("ThreatFox row %d sample: %s", idx, row)

        ioc = row.get("ioc_value")
        ioc_id = row.get("ioc_id")
        if not ioc or not ioc_id:
            continue
        ioc_type = row.get("ioc_type") or detect_ioc_type(ioc)
        process_ioc(
            seen, new_keys, ioc, ioc_type, "threatfox", counters,
            _id=ioc_id,
            first_seen=row.get("first_seen_utc"),
            last_seen=row.get("last_seen_utc"),
            threat_type=row.get("threat_type"),
            malware=row.get("malware_printable"),
            malware_alias=row.get("malware_alias"),
            confidence=row.get("confidence_level"),
            reference=row.get("reference"),
            tags=row.get("tags"),
            reporter=row.get("reporter"),
            severity="high" if "c2" in (row.get("threat_type") or "").lower() else "medium"
        )
def collect_urlhaus(seen, new_keys, counters):
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    data = fetch_url(url)
    if not data:
        logger.error("URLHaus feed returned no data")
        return

    # Remove only comment lines, keep header + data
    lines = []
    for line in data.splitlines():
        if line.startswith("#"):
            continue
        lines.append(line)
    buf = io.StringIO("\n".join(lines))

    # Explicit fieldnames for URLHaus
    fieldnames = [
        "id","dateadded","url","url_status","last_online",
        "threat","malware","urlhaus_link","reporter"
    ]
    reader = csv.DictReader(buf, fieldnames=fieldnames, skipinitialspace=True)
    next(reader, None)  # skip the header row

    for idx, row in enumerate(reader):
        if idx < 5:  # log first 5 rows for inspection
            logger.info("URLHaus row %d sample: %s", idx, row)

        url_val = row.get("url")
        id_val = row.get("id")
        if not url_val or not id_val:
            continue
        process_ioc(
            seen, new_keys, url_val, "url", "urlhaus", counters,
            _id=id_val,
            first_seen=row.get("dateadded"),
            last_seen=row.get("last_online"),
            url_status=row.get("url_status"),
            threat=row.get("threat"),
            malware=row.get("malware"),
            reporter=row.get("reporter"),
            severity="high" if "malware" in (row.get("threat") or "").lower() else "medium"
        )


# --- Session key retrieval ---
def get_session_key():
    key = os.environ.get("SPLUNK_ARG_8")
    if key:
        return key
    if len(sys.argv) > 8:
        return sys.argv[8]
    try:
        if not sys.stdin.isatty():
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                if "sessionKey=" in stdin_data:
                    return stdin_data.split("=", 1)[1]
                else:
                    return stdin_data
    except Exception:
        pass
    return None

# --- Main ---
def main():
    logger.info("Script started")
    session_key = get_session_key()
    if not session_key:
        logger.error("No session key provided. Check passAuth in inputs.conf.")
        sys.exit(1)

    collection = connect_kvstore(session_key)
    seen = load_seen_keys(collection)
    new_keys = []
    counters = {}

    logger.info("Starting feed collection cycle")
    collect_feodo(seen, new_keys, counters)
    collect_spamhaus(seen, new_keys, counters)
    collect_openphish(seen, new_keys, counters)
    collect_threatfox(seen, new_keys, counters)
    collect_urlhaus(seen, new_keys, counters)

    try:
        bulk_mark_seen(session_key, "ti_feeds_for_splunk", "ti_feed_state", new_keys)
    except Exception as e:
        logger.error("Bulk insert failed: %s", e)

    # Log per-feed counts
    for feed, count in counters.items():
        logger.info("Feed %s produced %d new records", feed, count)
    if not counters:
        logger.warning("No new records ingested from any feed")

    logger.info("Feed collection run completed successfully")

if __name__ == "__main__":
    main()
