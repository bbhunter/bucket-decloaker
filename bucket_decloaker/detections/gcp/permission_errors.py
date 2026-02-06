"""Permission error detection for GCP Storage."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class PermissionErrorsDetection(Detection):
    """Detect GCP bucket name from permission error responses."""

    name = "permission_errors_check"
    description = "Extract GCP bucket name from IAM permission error response"
    providers = [Provider.GCP]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.get(f'https://{domain}/', verify=False, timeout=10)
            response_content = r.content.decode('utf-8')

            # Check for GCP permission error strings
            permissions_error_strings = [
                '.iam.gserviceaccount.com does not have ',
                'caller does not have storage.objects.list '
            ]

            if any(error_string in response_content for error_string in permissions_error_strings):
                # Try to extract bucket name
                bucket_pattern = re.compile(r"access to (.*).</Details></Error>")
                match = bucket_pattern.search(response_content)

                if match:
                    bucket_name = match.group(1)
                    return self._success(
                        provider=Provider.GCP,
                        bucket_name=bucket_name,
                        message=f"GCP bucket found via permission error: {bucket_name}",
                    )

                # We know it's GCP even without bucket name
                return self._success(
                    provider=Provider.GCP,
                    message="GCP bucket detected via permission error (name not extracted)",
                )

            return self._failure("No GCP permission errors found")

        except Exception as e:
            return self._failure(f"GCP permission error check failed: {e}")
