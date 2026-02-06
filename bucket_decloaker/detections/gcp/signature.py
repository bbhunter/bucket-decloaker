"""Signature error detection for GCP Storage."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SignatureDetection(Detection):
    """Detect GCP bucket name by triggering a signature error."""

    name = "signature_check"
    description = "Extract GCP bucket name from signature error response"
    providers = [Provider.GCP]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            # Use HTTP (not HTTPS) with fake signature params
            url = f'http://{domain}/1?GoogleAccessId=1&Expires=1&Signature=YnVja2V0LWRpc2Nsb3Nlcg=='
            r = requests.get(url, verify=False, timeout=10)
            response_content = r.content.decode('utf-8')

            bucket_pattern = re.compile(r"/(.*)/1</StringToSign>")
            match = bucket_pattern.search(response_content)

            if match:
                bucket_name = match.group(1)
                return self._success(
                    provider=Provider.GCP,
                    bucket_name=bucket_name,
                    message=f"GCP bucket detected via signature error: {bucket_name}",
                )

            return self._failure("No GCP bucket found via signature trick")

        except Exception as e:
            return self._failure(f"GCP signature check error: {e}")
