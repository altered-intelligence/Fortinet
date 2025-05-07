#!/usr/bin/env python3
"""
fortios_nvd_feed_parser.py

Pull every FortiOS-related CVE published in 2024 from the NVD JSON feed (v1.1),
filter by CPE, and export to Excel.
"""

import io
import gzip
import json
import requests
import pandas as pd
from datetime import datetime

# ─── Configuration ──────────────────────────────────────────────────────────────

# NVD 2024 feed (JSON, gzipped) – use v1.1 path to avoid 404
FEED_URL    = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"
OUTPUT_XLSX = "fortios_vulns_2024.xlsx"

# Substring to match FortiOS CPE URIs
CPE_FILTER  = ":fortinet:fortios:"

# ─── Helper Functions ──────────────────────────────────────────────────────────

def download_and_decompress(url: str) -> dict:
    """
    Download the gzipped NVD JSON feed and return the parsed JSON object.
    """
    print(f"[*] Downloading NVD 2024 feed ({url}) …")
    resp = requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()
    compressed = io.BytesIO(resp.content)
    with gzip.GzipFile(fileobj=compressed) as f:
        data = json.load(f)
    return data

def extract_cpe_matches(nodes: list) -> list[str]:
    """
    Recursively walk all 'nodes' → 'children' and collect every cpe23Uri
    from cpe_match entries that contain CPE_FILTER.
    """
    uris = []
    for node in nodes:
        for m in node.get("cpe_match", []):
            uri = m.get("cpe23Uri", "")
            if CPE_FILTER in uri:
                uris.append(uri)
        for child in node.get("children", []):
            uris.extend(extract_cpe_matches([child]))
    return uris

def parse_feed(data: dict) -> list[dict]:
    """
    Walk through data["CVE_Items"], normalize dates, filter for FortiOS CPEs,
    and extract desired fields into a list of records.
    """
    records = []
    for item in data.get("CVE_Items", []):
        # CVE ID
        cve_id = item["cve"]["CVE_data_meta"]["ID"]

        # Published Date: normalize trailing 'Z' → '+00:00'
        date_str = item.get("publishedDate", "")
        if date_str.endswith("Z"):
            date_str = date_str[:-1] + "+00:00"
        try:
            pub_date = datetime.fromisoformat(date_str).date()
        except Exception:
            # fallback: drop timezone entirely
            pub_date = datetime.fromisoformat(date_str[:19]).date()

        # English description
        descs = item["cve"]["description"]["description_data"]
        description = next((d["value"] for d in descs if d["lang"] == "en"), "")

        # CVSS v3 (if available)
        impact = item.get("impact", {})
        m3     = impact.get("baseMetricV3", {})
        cvss3  = m3.get("cvssV3", {})
        score  = cvss3.get("baseScore", "")
        vector = cvss3.get("vectorString", "")

        # Affected CPEs: recursive extraction
        nodes       = item.get("configurations", {}).get("nodes", [])
        cpe_matches = extract_cpe_matches(nodes)
        if not cpe_matches:
            # skip entries that don't hit FortiOS
            continue

        # References
        refs = [r["url"] for r in item["cve"]["references"]["reference_data"]]

        records.append({
            "CVE ID":             cve_id,
            "Published Date":     pub_date,
            "Description":        description,
            "CVSS v3 Score":      score,
            "CVSS v3 Vector":     vector,
            "Affected CPEs":      "; ".join(sorted(set(cpe_matches))),
            "References":         "; ".join(refs)
        })

    return records

def main():
    # 1) Download & load the feed
    feed = download_and_decompress(FEED_URL)

    # 2) Parse & filter for FortiOS CVEs
    print("[*] Parsing feed and filtering for FortiOS CVEs…")
    vulns = parse_feed(feed)
    total = len(vulns)
    print(f"[*] {total} FortiOS CVEs found for 2024.")

    if total == 0:
        print("[!] No FortiOS CVEs detected—check CPE_FILTER or feed URL.")
        return

    # 3) Build DataFrame, sort, and export
    df = pd.DataFrame(vulns)
    df.sort_values("Published Date", inplace=True)
    df.to_excel(OUTPUT_XLSX, index=False)
    print(f"[✔] Exported {total} records to {OUTPUT_XLSX}")

if __name__ == "__main__":
    main()
