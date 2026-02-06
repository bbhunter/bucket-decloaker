"""HTTP header detection for cloud storage providers."""

from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class HTTPHeadersDetection(Detection):
    """Detect cloud storage provider from HTTP response headers."""

    name = "http_headers"
    description = "Check HTTP response headers for cloud storage provider indicators"
    providers = [Provider.AWS, Provider.GENERIC]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.get(f'https://{domain}/', verify=False, timeout=10)
            server_header = r.headers.get('Server', '')

            # AWS S3
            if 'AmazonS3' in server_header:
                return self._success(
                    provider=Provider.AWS,
                    message=f"Server header indicates S3: {server_header}",
                )

            # Could add more header checks here for other providers

            return self._failure("No cloud storage headers found")

        except requests.exceptions.RequestException as e:
            return self._failure(f"HTTP headers check error: {e}")
        except Exception as e:
            return self._failure(f"HTTP headers check error: {e}")
