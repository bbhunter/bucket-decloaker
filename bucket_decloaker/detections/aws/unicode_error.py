"""Unicode error detection for AWS S3."""

from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult, bcolors
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class UnicodeErrorDetection(Detection):
    """Detect S3 bucket using unicode characters in URL.

    Note: This detection is experimental and needs testing.
    """

    name = "unicode_error"
    description = "Check for S3 bucket via unicode character error response"
    providers = [Provider.AWS]
    confidence = Confidence.LOW  # Needs testing

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.get(f'https://{domain}/åäö', verify=False, timeout=10)
            response_content = r.content.decode('utf-8')

            # Print for debugging - this check needs testing
            print(bcolors.WARNING + "[/\\] This \"unicode_error\" function needs testing. "
                  "Please contact @BBerastegui if you see the bucket name in the response below." + bcolors.ENDC)
            print(response_content)
            print(bcolors.WARNING + "[/\\] This \"unicode_error\" function needs testing. "
                  "Please contact @BBerastegui if you see the bucket name in the response above." + bcolors.ENDC)

            # TODO: Add actual bucket name extraction once patterns are identified
            return self._failure("Unicode error check needs testing - see output above")

        except Exception as e:
            return self._failure(f"Unicode error check failed: {e}")
