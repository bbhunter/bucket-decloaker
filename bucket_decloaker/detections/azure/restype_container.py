"""Restype=container detection for Azure Blob Storage."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class RestypeContainerDetection(Detection):
    """Detect Azure blob storage using restype=container parameter."""

    name = "restype_container_check"
    description = "Detect Azure blob storage via restype=container parameter"
    providers = [Provider.AZURE]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        for scheme in ('https', 'http'):
            try:
                url = f'{scheme}://{domain}/?restype=container'
                r = requests.get(url, verify=False, timeout=10)
                content = r.content.decode('utf-8', errors='replace')

                # Azure-specific error codes in response to restype=container
                azure_indicators = [
                    'PublicAccessNotPermitted',
                    'ContainerNotFound',
                    'ResourceNotFound',
                    'AuthorizationPermissionMismatch',
                    'AuthenticationFailed',
                    '<EnumerationResults',
                ]

                for indicator in azure_indicators:
                    if indicator in content:
                        # Try to extract container name from response
                        container_pattern = re.compile(
                            r'<UriPath>https?://(.*?)/?\?restype=container</UriPath>'
                        )
                        match = container_pattern.search(content)
                        bucket_name = match.group(1) if match else None

                        return self._success(
                            provider=Provider.AZURE,
                            bucket_name=bucket_name,
                            message=f"Azure blob storage detected via restype=container ({indicator})",
                        )

            except Exception:
                continue

        return self._failure("No Azure blob storage found via restype=container")
