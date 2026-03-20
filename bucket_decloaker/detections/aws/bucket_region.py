"""Bucket region discovery for AWS S3."""

from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class BucketRegionDetection(Detection):
    """Detect AWS S3 and discover bucket region via x-amz-bucket-region header."""

    name = "bucket_region_check"
    description = "Discover S3 bucket region from x-amz-bucket-region header"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.head(f'https://{domain}/', verify=False, timeout=10, allow_redirects=True)
            region = r.headers.get('x-amz-bucket-region')

            if region:
                return self._success(
                    provider=Provider.AWS,
                    message=f"S3 bucket region: {region}",
                )

            # Also try GET — some S3 configs don't return headers on HEAD
            r = requests.get(f'https://{domain}/', verify=False, timeout=10)
            region = r.headers.get('x-amz-bucket-region')

            if region:
                return self._success(
                    provider=Provider.AWS,
                    message=f"S3 bucket region: {region}",
                )

            return self._failure("No x-amz-bucket-region header found")

        except Exception as e:
            return self._failure(f"Bucket region check error: {e}")
