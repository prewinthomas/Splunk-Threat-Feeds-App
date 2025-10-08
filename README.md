# Splunk-Threat-Feeds-App
Threat Intel OSINT Feeds for Splunk
Overview
Threat Intel OSINT Feeds for Splunk is a Splunk app that automates the collection of open‑source threat intelligence (OSINT) feeds and ingests them into Splunk for security monitoring, enrichment, and correlation.

The app provides:

Scheduled scripted inputs to fetch threat intel feeds (IP, domain, URL, hash indicators).

A simple control panel to enable/disable feeds and adjust polling intervals.

Normalized sourcetypes (ti:openfeeds) for easy searching and correlation.

A dashboard to monitor feed status and configuration.

Natural Language search to search details on the feeds.

This app is designed to complement Splunk Enterprise Security (ES) or any custom security monitoring deployment by enriching events with external threat intelligence.

Features
🔄 Automated Feed Collection: Fetches OSINT feeds on a configurable schedule.

🛡️ Threat Intel Normalization: Stores indicators in a consistent format for easy correlation.

📊 Dashboard & Controls: View current feed status, adjust intervals, and enable/disable feeds.

🌙 Natural Language Search.

Installation
Download the app package (.spl or .tgz).

Install via Splunk Web: Apps → Manage Apps → Install app from file or place it under $SPLUNK_HOME/etc/apps/.

Restart Splunk if required.

Configuration
Navigate to the Threat Intel OSINT Feeds dashboard.

Use the control panel to:

Enable/disable the feed collector script.

Adjust the polling interval (default: 3600 seconds).

Verify that events are being indexed into the ti_feeds index with sourcetype ti:openfeeds.

Usage
Search for collected indicators:

spl
index=ti_feeds sourcetype=ti:openfeeds

Requirements
-Splunk Enterprise 9.x+(tested on 9.x).

-Network connectivity to OSINT feed sources.

-Appropriate index (ti_feeds) created and accessible.
