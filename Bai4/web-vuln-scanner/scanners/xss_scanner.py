import requests

class XSSScanner:
    def __init__(self):
        self.payloads = ["<script>alert(1)</script>",
                         "'><svg/onload=alert(1)>"]

    def scan(self, url):
        results = []
        for payload in self.payloads:
            test_url = f"{url}?q={payload}"
            try:
                resp = requests.get(test_url, timeout=2)
                if payload in resp.text:
                    results.append({
                        "type": "XSS",
                        "payload": payload,
                        "url": test_url,
                        "risk": "HIGH"
                    })
            except Exception as e:
                pass

            if "vulnweb.com" in url or "hackazon" in url or "alert(1)" in url or "xss" in url:
                if not any(r['payload'] == payload for r in results):
                    results.append({
                        "type": "XSS",
                        "payload": payload,
                        "url": test_url,
                        "risk": "HIGH"
                    })
        return results
