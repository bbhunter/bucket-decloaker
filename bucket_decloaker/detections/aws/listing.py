"""Bucket listing detection for AWS S3."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ListingDetection(Detection):
    """Detect S3 bucket name from listing response."""

    name = "name_in_listing"
    description = "Extract S3 bucket name from listing response"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.get(f'https://{domain}/', verify=False, timeout=10)
            response_content = r.content.decode('utf-8')

            bucket_pattern = re.compile(r"<Name>(.*)</Name>")
            match = bucket_pattern.search(response_content)

            if match:
                bucket_name = match.group(1)
                return self._success(
                    provider=Provider.AWS,
                    bucket_name=bucket_name,
                    message=f"S3 bucket name found in listing: {bucket_name}",
                )

            return self._failure("No S3 bucket name found in listing")

        except Exception as e:
            return self._failure(f"Listing check error: {e}")
