Splunk-Threat-Intel-AI-Enrichment-App
This Splunk App enriches Indicators of Compromise (IOCs) (IPs, domains, URLs, file hashes) by querying multiple external threat intelligence sources, then correlates enriched IOCs into campaigns. A key feature of this app is its use of AI‑driven natural language generation to produce clear, human‑readable IOC summaries and campaign summaries, making threat intelligence more accessible to both analysts and decision‑makers.



📝 Detailed Logging – all enrichment activity is logged to:$SPLUNK_HOME/var/log/splunk/enrichioc.log

📋 Prerequisites Before installing, ensure the following:

Splunk Enterprise 9.2+ or Splunk Cloud

Python 3.7+ runtime

API Keys for OTX, AbuseIPDB, GreyNoise, URLHaus - (Free version/Paid)

KV Store enabled

Admin role for installation and setup

Outbound HTTPS access to enrichment APIs

Index Creation: The app expects an index named ti_enrich for storing enrichment results. You can create it by adding the following stanza to indexes.conf (on the same server or on your indexer):

[ti_enrich] homePath = $SPLUNK_DB/ti_enrich/db coldPath = $SPLUNK_DB/ti_enrich/colddb thawedPath = $SPLUNK_DB/ti_enrich/thaweddb maxTotalDataSizeMB = 5000 frozenTimePeriodInSecs = 7776000 # 90 days retention Uncomment and copy this stanza to your local folder if creating locally or configure it on your indexer(s) if running in a distributed environment

⚙️ Installation Install the App Package as .spl and install via Manage Apps → Install app from file

Restart Splunk if prompted

Configure API Keys

Use the Threat Intel API Key Configuration dashboard Enter API keys for OTX, AbuseIPDB, GreyNoise, URLHaus Keys are stored in the ti_api_keys lookup (masked in UI)

KV Store Collections Ensure these collections exist (auto‑created if not):

ioc_cache edges nodes campaign_cache

🔎 Usage Enrich IOCs | enrichioc value="8.8.8.8"

