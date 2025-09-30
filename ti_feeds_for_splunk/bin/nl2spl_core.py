# nl2spl_core.py
import re

def build_spl(query_text, index="ti_feeds"):
    from nl2spl_command import extract_entities  # or move extract_entities here

    malware, earliest, latest = extract_entities(query_text)
    time_clause = f" earliest={earliest} latest={latest}" if earliest else ""

    if malware:
        return f'index={index} malware="{malware}"{time_clause} | stats count by malware feed value'
    else:
        return f'index={index}{time_clause} | stats count by malware feed value /* Fallback: no malware keyword detected */'
