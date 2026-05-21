"""
cve.py — CVE Database Integration
Queries NVD (National Vulnerability Database) for real CVE data
Free API, no key required for basic use
"""
import os, httpx
from datetime import datetime
from typing import List, Dict, Optional

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # optional - higher rate limits

async def search_cves_by_keyword(keyword: str, limit: int = 5) -> List[dict]:
    """Search NVD for CVEs matching a keyword (package name, service, etc.)"""
    try:
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit,
            "startIndex": 0,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(NVD_BASE, params=params, headers=headers)
            if r.status_code != 200:
                return []
            data = r.json()
            return _parse_cves(data.get("vulnerabilities", []))
    except Exception as e:
        print(f"[CVE] Search error: {e}")
        return []

async def get_cve_by_id(cve_id: str) -> Optional[dict]:
    """Get full details for a specific CVE"""
    try:
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        params = {"cveId": cve_id}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(NVD_BASE, params=params, headers=headers)
            if r.status_code != 200:
                return None
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return _parse_cve(vulns[0])
            return None
    except Exception as e:
        print(f"[CVE] Lookup error: {e}")
        return None

async def enrich_scan_with_cves(packages: List[dict]) -> List[dict]:
    """Take scan package list and add CVE data to vulnerable ones"""
    enriched = []
    for pkg in packages:
        name    = pkg.get("name", "")
        version = pkg.get("version", "")
        if not name:
            enriched.append(pkg)
            continue
        # Search for CVEs for this package
        cves = await search_cves_by_keyword(f"{name} {version}", limit=3)
        enriched.append({**pkg, "cves": cves, "cve_count": len(cves)})
    return enriched

def _parse_cves(vulns: List[dict]) -> List[dict]:
    return [_parse_cve(v) for v in vulns if v]

def _parse_cve(vuln: dict) -> dict:
    cve   = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    desc  = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    # CVSS v3 score
    score    = 0.0
    severity = "unknown"
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            score    = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN").lower()
            break
    if not score and "cvssMetricV2" in metrics:
        m2 = metrics["cvssMetricV2"]
        if m2:
            score    = m2[0].get("cvssData", {}).get("baseScore", 0.0)
            severity = m2[0].get("baseSeverity", "UNKNOWN").lower()
    # Published date
    published = cve.get("published", "")[:10]
    # References
    refs = [r.get("url","") for r in cve.get("references", [])[:3]]
    return {
        "id":         cve_id,
        "description": desc[:300] + ("..." if len(desc) > 300 else ""),
        "score":      score,
        "severity":   severity,
        "published":  published,
        "references": refs,
        "url":        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    }

async def get_recent_cves(days: int = 7, limit: int = 10) -> List[dict]:
    """Get recently published CVEs"""
    from datetime import timedelta
    end   = datetime.utcnow()
    start = end - timedelta(days=days)
    try:
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate":   end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": limit,
            "cvssV3Severity": "CRITICAL"
        }
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(NVD_BASE, params=params, headers=headers)
            if r.status_code != 200:
                return []
            return _parse_cves(r.json().get("vulnerabilities", []))
    except Exception as e:
        print(f"[CVE] Recent error: {e}")
        return []
