"""ACL endpoint detection for AWS S3."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ACLEndpointDetection(Detection):
    """Detect S3 bucket info via the ?acl endpoint."""

    name = "acl_endpoint_check"
    description = "Extract S3 bucket info from ACL endpoint response"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.get(f'https://{domain}/?acl', verify=False, timeout=10)
            content = r.content.decode('utf-8', errors='replace')

            # The ?acl response contains AccessControlPolicy with Owner info
            # even on AccessDenied the error may contain bucket details
            owner_pattern = re.compile(r'<Owner>\s*<ID>(.*?)</ID>', re.DOTALL)
            match = owner_pattern.search(content)

            if match:
                owner_id = match.group(1)
                return self._success(
                    provider=Provider.AWS,
                    message=f"S3 ACL endpoint returned owner ID: {owner_id[:16]}...",
                )

            # Check for S3-specific AccessDenied with bucket reference
            if '<Code>AccessDenied</Code>' in content and 'HostId' in content:
                return self._success(
                    provider=Provider.AWS,
                    message="S3 confirmed via ACL endpoint (AccessDenied response)",
                )

            return self._failure("No S3 ACL response detected")

        except Exception as e:
            return self._failure(f"ACL endpoint check error: {e}")
