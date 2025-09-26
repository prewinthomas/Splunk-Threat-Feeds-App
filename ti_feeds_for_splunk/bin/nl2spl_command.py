#!/usr/bin/env python3
import sys, csv, logging, re

# Optional: import your translator logic
try:
    from nl2spl_core import build_spl
except ImportError:
    build_spl = None

# Configure logging to stderr (Splunk captures this in search.log)
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

def sanitize_spl(s: str) -> str:
    """
    Remove accidental leading/trailing quotes and unescape \" if present.
    """
    if not s:
        return s
    # Strip leading/trailing quotes
    s = re.sub(r'^\s*["\'](.*)["\']\s*$', r'\1', s)
    # Replace escaped quotes with normal quotes
    s = s.replace(r'\"', '"').replace(r"\'", "'")
    return s.strip()

if __name__ == "__main__":
    args = sys.argv[1:]
    query_text = " ".join(args).strip()
    logging.debug("nl2spl received args: %s", args)

    if not query_text:
        spl = "ERROR: missing query text"
    else:
        if build_spl:
            try:
                spl = build_spl(query_text, index="ti_feeds")
                logging.debug("Generated SPL before sanitize: %s", spl)
            except Exception as e:
                logging.exception("Error in build_spl")
                spl = f"ERROR: {str(e)}"
        else:
            # Fallback if no translator is available
            spl = f'index=ti_feeds | head 10 /* {query_text} */'

    # Sanitize the SPL string to remove unwanted quotes
    spl = sanitize_spl(spl)
    logging.debug("Final SPL after sanitize: %s", spl)

    # Output as CSV (header + row)
    writer = csv.writer(sys.stdout)
    writer.writerow(["spl"])
    writer.writerow([spl])
