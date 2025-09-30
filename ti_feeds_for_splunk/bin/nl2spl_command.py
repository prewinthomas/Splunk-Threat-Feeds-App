#!/usr/bin/env python3
import sys, csv, logging, re
from typing import Optional, Tuple

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

GENERIC_MALWARE_WORDS = {
    "all", "new", "malware", "threat", "threats", "ioc", "iocs",
    "indicator", "indicators", "c2", "server", "servers",
    "domain", "domains", "hash", "hashes", "feed", "feeds",
    "from", "this", "week", "month", "quarter", "year", "days", "day",
    "hit", "hits", "records", "entries", "events"
}


KNOWN_FEEDS = ["feodo", "openphish", "spamhaus_drop", "threatfox", "urlhaus"]

def sanitize_spl(s: str) -> str:
    if not s:
        return s
    s = re.sub(r'^\s*["\'](.*)["\']\s*$', r'\1', s)
    s = s.replace(r'\"', '"').replace(r"\'", "'")
    return s.strip()

def extract_malware(query_text: str) -> Optional[str]:
    m = re.search(r'\b(?:all|new)\s+(.+?)(?:\s+(?:from|in|on|for|during)\b|$)',
                  query_text, re.IGNORECASE)
    phrase = None
    if m:
        phrase = m.group(1).strip()
    else:
        m2 = re.search(r'\b([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)*)\b',
                       query_text)
        if m2:
            phrase = m2.group(1).strip()
    if not phrase:
        return None
    phrase = re.sub(r'^[^\w]+|[^\w]+$', '', phrase)
    phrase = re.sub(r'\s+', ' ', phrase).strip()
    tokens = [t for t in phrase.split() if t.lower() not in GENERIC_MALWARE_WORDS]
    if not tokens:
        return None
    clauses = [f'malware="*{t}*"' for t in tokens]
    return " OR ".join(clauses)

def extract_feed(query_text: str) -> Optional[str]:
    for feed in KNOWN_FEEDS:
        if re.search(rf'\b{feed}\b', query_text, re.IGNORECASE):
            return f'feed="*{feed}*"'
    return None

def extract_value(query_text: str) -> Optional[str]:
    # IPv4
    m = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', query_text)
    if m:
        return f'value="*{m.group(0)}*"'
    # URL
    m = re.search(r'https?://[^\s]+', query_text)
    if m:
        return f'value="*{m.group(0)}*"'
    # Domain
    m = re.search(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', query_text, re.IGNORECASE)
    if m:
        return f'value="*{m.group(0)}*"'
    # Hashes
    m = re.search(r'\b[a-fA-F0-9]{32}\b', query_text)  # MD5
    if m:
        return f'value="*{m.group(0)}*"'
    m = re.search(r'\b[a-fA-F0-9]{40}\b', query_text)  # SHA1
    if m:
        return f'value="*{m.group(0)}*"'
    m = re.search(r'\b[a-fA-F0-9]{64}\b', query_text)  # SHA256
    if m:
        return f'value="*{m.group(0)}*"'
    return None

def extract_time(query_text: str) -> Tuple[Optional[str], str]:
    q = query_text.lower()
    earliest, latest = None, "now"

    if re.search(r'\blast day last month\b', q):
        earliest = "-1mon@mon+1mon-1d@d"; latest = "-1mon@mon+1mon"
    elif re.search(r'\blast month\b', q) or re.search(r'\bpast month\b', q):
        earliest = "-1mon@mon"
    elif re.search(r'\bthis month\b', q):
        earliest = "@mon"
    elif re.search(r'\blast quarter\b', q) or re.search(r'\bpast quarter\b', q):
        earliest = "-1q@q"
    elif re.search(r'\bthis quarter\b', q):
        earliest = "@q"
    elif re.search(r'\blast year\b', q) or re.search(r'\bpast year\b', q):
        earliest = "-1y@y"
    elif re.search(r'\bthis year\b', q):
        earliest = "@y"
    elif re.search(r'\blast week\b', q):
        earliest = "-1w@w"; latest = "@w"
    elif re.search(r'\bthis week\b', q):
        earliest = "@w"
    elif re.search(r'last\s*30\s*days', q) or re.search(r'past\s*30\s*days', q):
        earliest = "-30d@d"
    elif re.search(r'\bthis\s*30\s*days\b', q):
        earliest = "-30d@d"
    elif m := re.search(r'(?:last|past)\s*(\d+)\s*days', q):
        n = m.group(1); earliest = f"-{n}d@d"
    elif m := re.search(r'\bthis\s*(\d+)\s*days\b', q):
        n = m.group(1); earliest = f"-{n}d@d"
    elif re.search(r'last 24 hours', q) or re.search(r'past 24 hours', q):
        earliest = "-24h"
    elif re.search(r'\blast day\b', q):
        earliest = "-1d"
    elif re.search(r'\btoday\b', q):
        earliest = "@d"
    elif re.search(r'\byesterday\b', q):
        earliest, latest = "-1d@d", "@d"

    return earliest, latest

if __name__ == "__main__":
    args = sys.argv[1:]
    query_text = " ".join(args).strip()
    logging.debug("nl2spl received args: %s", args)

    if not query_text:
        spl = "ERROR: missing query text"
    else:
        malware_clause = extract_malware(query_text)
        feed_clause = extract_feed(query_text)
        value_clause = extract_value(query_text)
        earliest, latest = extract_time(query_text)

        time_clause = f" earliest={earliest} latest={latest}" if earliest else " latest=now"

        clauses = []
        if malware_clause:
            clauses.append(f'({malware_clause})')
        if feed_clause:
            clauses.append(feed_clause)
        if value_clause:
            clauses.append(value_clause)

        where = " ".join(clauses)
        if where:
            spl = f'index=ti_feeds {where}{time_clause} | stats count by malware feed value'
        else:
            spl = f'index=ti_feeds{time_clause} | stats count by malware feed value'
            logging.debug("No specific malware, feed, or value detected")

    spl = sanitize_spl(spl)
    logging.debug("Final SPL after sanitize: %s", spl)

    writer = csv.writer(sys.stdout, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["spl"])
    writer.writerow([spl])
