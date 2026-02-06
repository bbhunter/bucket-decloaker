"""SOAP endpoint detection for AWS S3."""

from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SOAPDetection(Detection):
    """Detect S3 bucket by querying the /soap endpoint."""

    name = "soap_check"
    description = "Check for S3 bucket via SOAP endpoint"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.post(f'https://{domain}/soap', verify=False, timeout=10)
            response_content = r.content.decode('utf-8')

            if '>Missing SOAPAction header<' in response_content:
                return self._success(
                    provider=Provider.AWS,
                    message="S3 bucket detected via /soap endpoint",
                )

            return self._failure("No S3 bucket found via SOAP check")

        except Exception as e:
            return self._failure(f"SOAP check error: {e}")
