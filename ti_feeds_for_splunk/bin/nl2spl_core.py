# nl2spl_core.py
def build_spl(query_text, index="ti_feeds"):
    # Very simple placeholder logic
    if "cobalt" in query_text.lower():
        return f'index={index} malware="Cobalt Strike" earliest=@w latest=now | stats count by value feed'
    return f'index={index} earliest=@w latest=now | stats count by value feed'
