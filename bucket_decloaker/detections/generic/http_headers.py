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
    providers = [Provider.AWS, Provider.GCP, Provider.AZURE, Provider.GENERIC]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            r = requests.get(f'https://{domain}/', verify=False, timeout=10)
            headers = r.headers
            server_header = headers.get('Server', '')

            # AWS S3
            if 'AmazonS3' in server_header:
                return self._success(
                    provider=Provider.AWS,
                    message=f"Server header indicates S3: {server_header}",
                )

            # GCP Storage — x-goog-* headers
            gcp_headers = [k for k in headers if k.lower().startswith('x-goog-')]
            if gcp_headers:
                details = ', '.join(f'{h}: {headers[h]}' for h in gcp_headers[:5])
                return self._success(
                    provider=Provider.GCP,
                    message=f"GCP headers detected: {details}",
                )

            # Azure Blob Storage — x-ms-* headers
            azure_headers = [k for k in headers if k.lower().startswith('x-ms-')]
            if azure_headers:
                details = ', '.join(f'{h}: {headers[h]}' for h in azure_headers[:5])
                return self._success(
                    provider=Provider.AZURE,
                    message=f"Azure headers detected: {details}",
                )

            return self._failure("No cloud storage headers found")

        except requests.exceptions.RequestException as e:
            return self._failure(f"HTTP headers check error: {e}")
        except Exception as e:
            return self._failure(f"HTTP headers check error: {e}")
