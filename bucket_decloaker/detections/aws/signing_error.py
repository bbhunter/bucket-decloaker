"""Signing error detection for AWS S3."""

import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult, UNIQUE_FILENAME
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SigningErrorDetection(Detection):
    """Detect S3 bucket name by triggering a signing error with a valid AWS key."""

    name = "signing_error"
    description = "Extract S3 bucket name from signing error response"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH
    requires_params = ["aws_key"]

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        aws_key = context.get('aws_key') if context else None

        if not aws_key:
            return self._failure("Signing error check requires --aws-key parameter")

        try:
            headers = {
                "Authorization": f"AWS {aws_key}:x",
                "Date": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            }

            r = requests.get(
                f'https://{domain}/{UNIQUE_FILENAME}?112233',
                headers=headers,
                verify=False,
                timeout=10
            )
            response_content = r.content.decode('utf-8')

            bucket_pattern = re.compile(r"/(.*?)/.*</StringToSign>")
            match = bucket_pattern.search(response_content)

            if match:
                bucket_name = match.group(1)
                return self._success(
                    provider=Provider.AWS,
                    bucket_name=bucket_name,
                    message=f"S3 bucket name extracted from signing error: {bucket_name}",
                )

            return self._failure("No bucket name found in signing error response")

        except Exception as e:
            return self._failure(f"Signing error check failed: {e}")
