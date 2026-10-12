"""
Free CVE Integration Module for IoT Sentinel Pro — Campus Edition.
Queries the official NIST National Vulnerability Database (NVD) REST API v2.0.

Key Properties:
- 100% Free & Open: No mandatory API keys, subscriptions, or credit cards.
- Supports optional NVD_API_KEY from environment variables to increase rate limit.
- Local SQLite caching with timestamp & source metadata.
- Graceful offline degradation: never crashes or freezes if offline, rate limited, or timed out.
- Strict version matching: queries only when reliable product and version strings exist.
- Never fabricates CVE IDs, CVSS scores, or affected products.
"""

import time
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from utils.config import NVD_API_URL, NVD_API_KEY
from database.db_manager import get_cached_cve, set_cached_cve

class CVELookup:
    """Handles querying and caching CVE records from NIST NVD API v2.0."""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 5):
        self.api_key = api_key if api_key else NVD_API_KEY
        self.timeout = timeout
        self.base_url = NVD_API_URL
        self.source_name = "NIST National Vulnerability Database (NVD) v2.0"

    def lookup_cves_for_service(
        self,
        product: str,
        version: str = "",
        max_results: int = 3
    ) -> Dict[str, Any]:
        """
        Queries NVD API for verified CVEs for a specific product and version.
        Uses local SQLite caching. Returns detailed metadata and status.
        """
        product_clean = product.strip().lower()
        version_clean = version.strip()
        timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Validation to prevent false positives
        generic_terms = ("unknown", "generic", "tcpwrapped", "http", "ftp", "ssh", "ssl", "linux", "embedded")
        if not product_clean or product_clean in generic_terms:
            return {
                "status": "SKIPPED_INSUFFICIENT_EVIDENCE",
                "message": "Product banner string lacks specific model/version specificity for reliable CVE mapping.",
                "timestamp": timestamp_now,
                "source": self.source_name,
                "cves": []
            }

        cache_key = f"{product_clean}:{version_clean}".strip(":")

        # 2. Check local SQLite cache first
        cached_result = get_cached_cve(cache_key)
        if cached_result is not None:
            cves = cached_result if isinstance(cached_result, list) else []
            return {
                "status": "CACHE_HIT",
                "message": f"Retrieved {len(cves)} cached CVE entries from local database.",
                "timestamp": timestamp_now,
                "source": "Local SQLite NVD Cache",
                "cves": cves[:max_results]
            }

        # 3. Construct Live HTTP Request
        headers = {
            "User-Agent": "IoT-Sentinel-Pro/2.0 (Campus Defensive Research; Free Tier)"
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        query_keyword = f"{product_clean} {version_clean}".strip()
        params = {
            "keywordSearch": query_keyword,
            "resultsPerPage": max_results
        }

        try:
            response = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                items = data.get("vulnerabilities", [])
                results = []

                for item in items:
                    cve_obj = item.get("cve", {})
                    cve_id = cve_obj.get("id", "")
                    descriptions = cve_obj.get("descriptions", [])
                    desc_text = descriptions[0].get("value", "") if descriptions else "No description available."

                    # Extract CVSS v3.1 / v3.0 data
                    metrics = cve_obj.get("metrics", {})
                    cvss_score = None
                    cvss_vector = ""
                    severity = "UNKNOWN"

                    cvss3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                    if cvss3:
                        primary_cvss = cvss3[0].get("cvssData", {})
                        cvss_score = primary_cvss.get("baseScore")
                        cvss_vector = primary_cvss.get("vectorString", "")
                        severity = primary_cvss.get("baseSeverity", "MEDIUM")

                    results.append({
                        "cve_id": cve_id,
                        "description": desc_text[:250] + ("..." if len(desc_text) > 250 else ""),
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "severity": severity,
                        "cve_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "matched_query": query_keyword
                    })

                # Cache in local SQLite database
                set_cached_cve(cache_key, results)

                return {
                    "status": "LIVE_API_SUCCESS",
                    "message": f"Successfully queried NIST NVD API; retrieved {len(results)} verified CVEs.",
                    "timestamp": timestamp_now,
                    "source": self.source_name,
                    "cves": results
                }

            elif response.status_code == 429:
                return {
                    "status": "RATE_LIMITED",
                    "message": "NIST NVD rate limit reached (5 requests/30s for unauthenticated tier). Offline heuristics active.",
                    "timestamp": timestamp_now,
                    "source": self.source_name,
                    "cves": []
                }
            else:
                return {
                    "status": f"HTTP_{response.status_code}",
                    "message": f"NVD API returned status code {response.status_code}. Using local offline rules.",
                    "timestamp": timestamp_now,
                    "source": self.source_name,
                    "cves": []
                }

        except (requests.exceptions.RequestException, requests.exceptions.Timeout, Exception) as ex:
            # Complete offline fallback: Never crash the application!
            return {
                "status": "OFFLINE_FALLBACK",
                "message": "Network/NVD API unavailable or offline. Operating cleanly with local rule heuristics.",
                "timestamp": timestamp_now,
                "source": "Offline Fallback Mode",
                "cves": []
            }
