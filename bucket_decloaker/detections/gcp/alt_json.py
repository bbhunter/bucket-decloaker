"""Alt=json trick detection for GCP Storage."""

import json
import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class AltJsonDetection(Detection):
    """Detect GCP bucket name using ?alt=json parameter to trigger JSON error responses."""

    name = "alt_json_check"
    description = "Extract GCP bucket info via alt=json parameter"
    providers = [Provider.GCP]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        for scheme in ('https', 'http'):
            try:
                url = f'{scheme}://{domain}/?alt=json'
                r = requests.get(url, verify=False, timeout=10)
                content = r.content.decode('utf-8', errors='replace')

                # GCP JSON error responses contain structured error info
                try:
                    data = json.loads(content)
                    error = data.get('error', {})
                    errors = error.get('errors', [])

                    for err in errors:
                        domain_field = err.get('domain', '')
                        if domain_field == 'global' and 'storage' in err.get('reason', '').lower():
                            message = err.get('message', '')
                            return self._success(
                                provider=Provider.GCP,
                                message=f"GCP Storage JSON error: {message}",
                            )

                    # Check for generic GCP storage indicators in JSON
                    if error.get('code') in (401, 403) and 'storage' in str(errors).lower():
                        return self._success(
                            provider=Provider.GCP,
                            message=f"GCP Storage confirmed via JSON error (HTTP {error.get('code')})",
                        )
                except (json.JSONDecodeError, AttributeError):
                    pass

                # Fallback: check for GCP-specific content in non-JSON response
                if 'storage.objects.list' in content or 'storage.googleapis.com' in content:
                    return self._success(
                        provider=Provider.GCP,
                        message="GCP Storage detected via alt=json response content",
                    )

            except Exception:
                continue

        return self._failure("No GCP bucket found via alt=json trick")
