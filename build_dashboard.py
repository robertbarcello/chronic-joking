#!/usr/bin/env python3
"""Bake whoop_data.json into dashboard.html -> whoop_dashboard.html (one self-contained file).

    python3 build_dashboard.py [whoop_data.json] [whoop_dashboard.html]

dashboard.html also works on its own: open it and drop whoop_data.json onto the page.
"""
import json
import sys

src = sys.argv[1] if len(sys.argv) > 1 else "whoop_data.json"
dst = sys.argv[2] if len(sys.argv) > 2 else "whoop_dashboard.html"
PLACEHOLDER = "/*__WHOOP_DATA__*/null"

with open(src) as f:
    data = json.load(f)
with open("dashboard.html") as f:
    html = f.read()
if PLACEHOLDER not in html:
    sys.exit("dashboard.html is missing the data placeholder.")
# "</" must not appear inside an inline <script>.
payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
with open(dst, "w") as f:
    f.write(html.replace(PLACEHOLDER, payload, 1))
print(f"Wrote {dst} ({len(data.get('days', {}))} days)")
