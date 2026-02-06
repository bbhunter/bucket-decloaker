"""Comp parameter detection for Azure Blob Storage."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult, UNIQUE_FILENAME
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class CompParameterDetection(Detection):
    """Detect Azure blob storage by appending comp=list parameter."""

    name = "comp_parameter_check"
    description = "Extract Azure blob storage name using comp=list parameter"
    providers = [Provider.AZURE]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            url = f'http://{domain}/{UNIQUE_FILENAME}/?comp=list'
            r = requests.get(url, verify=False, timeout=10)
            response_content = r.content.decode('utf-8')

            blob_pattern = re.compile(
                rf"<UriPath>https?:\/\/(.*)/{UNIQUE_FILENAME}\/\?comp=list<\/UriPath>"
            )
            match = blob_pattern.search(response_content)

            if match:
                bucket_name = match.group(1)
                return self._success(
                    provider=Provider.AZURE,
                    bucket_name=bucket_name,
                    message=f"Azure blob storage detected via comp=list: {bucket_name}",
                )

            return self._failure("No Azure blob storage found via comp=list")

        except Exception as e:
            return self._failure(f"Azure comp parameter check error: {e}")
