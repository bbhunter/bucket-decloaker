"""Direct URL check for bucket existence."""

from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class URLCheckDetection(Detection):
    """Check if a bucket exists by querying provider URLs directly."""

    name = "url_check"
    description = "Check if domain-named bucket exists on AWS S3 or GCP Storage"
    providers = [Provider.AWS, Provider.GCP, Provider.GENERIC]
    confidence = Confidence.LOW  # Not certain the bucket is actually serving the domain

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        not_found_text = b'The specified bucket does not exist'

        # Check AWS S3
        try:
            s3_url = f'https://{domain}.s3.amazonaws.com'
            r = requests.get(s3_url, verify=False, timeout=10)
            if not_found_text not in r.content:
                return self._success(
                    provider=Provider.AWS,
                    bucket_name=domain,
                    confidence=Confidence.LOW,
                    message=f"S3 bucket exists with domain name: {domain}",
                )
        except Exception:
            pass

        # Check GCP Storage
        try:
            gcp_url = f'https://storage.googleapis.com/{domain}'
            r = requests.get(gcp_url, verify=False, timeout=10)
            if not_found_text not in r.content:
                return self._success(
                    provider=Provider.GCP,
                    bucket_name=domain,
                    confidence=Confidence.LOW,
                    message=f"GCP bucket exists with domain name: {domain}",
                )
        except Exception:
            pass

        return self._failure("No bucket found with domain name at provider URLs")
