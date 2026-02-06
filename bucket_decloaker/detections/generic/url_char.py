"""URL character trick detection for AWS S3."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class URLCharDetection(Detection):
    """Detect S3 bucket name using URL %C0 character trick."""

    name = "url_char_check"
    description = "Extract S3 bucket name using %C0 character in URL"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.get(f'https://{domain}/1%C0', verify=False, timeout=10)
            response_content = r.content.decode('utf-8')

            bucket_pattern = re.compile(r"<URI>\/(.*?)\/.*<\/URI>")
            match = bucket_pattern.search(response_content)

            if match:
                bucket_name = match.group(1)
                return self._success(
                    provider=Provider.AWS,
                    bucket_name=bucket_name,
                    message=f"S3 bucket detected via URL %C0 trick: {bucket_name}",
                )

            return self._failure("No S3 bucket found with URL %C0 trick")

        except Exception as e:
            return self._failure(f"URL char check error: {e}")
