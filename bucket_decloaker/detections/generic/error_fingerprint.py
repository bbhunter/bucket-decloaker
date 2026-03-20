"""Error page fingerprinting for cloud storage providers."""

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult, UNIQUE_FILENAME
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Provider-specific error page patterns
ERROR_PATTERNS = [
    # AWS S3 XML error responses
    (re.compile(r'<Code>NoSuchBucket</Code>'), Provider.AWS, "S3 NoSuchBucket error"),
    (re.compile(r'<Code>AccessDenied</Code>.*<HostId>', re.DOTALL), Provider.AWS, "S3 AccessDenied error"),
    (re.compile(r'<Code>NoSuchKey</Code>'), Provider.AWS, "S3 NoSuchKey error"),
    (re.compile(r'<Code>PermanentRedirect</Code>'), Provider.AWS, "S3 PermanentRedirect error"),
    (re.compile(r'<Code>AllAccessDisabled</Code>'), Provider.AWS, "S3 AllAccessDisabled error"),
    (re.compile(r'<Endpoint>.*\.s3\.amazonaws\.com</Endpoint>'), Provider.AWS, "S3 endpoint in error"),

    # GCP Storage error responses
    (re.compile(r'<Code>AccessDenied</Code>.*<Details>', re.DOTALL), Provider.GCP, "GCP AccessDenied error"),
    (re.compile(r'storage\.objects\.(get|list|create)'), Provider.GCP, "GCP Storage IAM permission error"),
    (re.compile(r'cloud\.google\.com/storage'), Provider.GCP, "GCP Storage documentation link"),
    (re.compile(r'<StringToSign>'), Provider.GCP, "GCP StringToSign in error"),

    # Azure Blob Storage error responses
    (re.compile(r'<Code>BlobNotFound</Code>'), Provider.AZURE, "Azure BlobNotFound error"),
    (re.compile(r'<Code>ContainerNotFound</Code>'), Provider.AZURE, "Azure ContainerNotFound error"),
    (re.compile(r'<Code>ResourceNotFound</Code>'), Provider.AZURE, "Azure ResourceNotFound error"),
    (re.compile(r'<Code>PublicAccessNotPermitted</Code>'), Provider.AZURE, "Azure PublicAccessNotPermitted error"),
    (re.compile(r'<Code>AuthenticationFailed</Code>.*x-ms-', re.DOTALL), Provider.AZURE, "Azure auth error"),
]


class ErrorFingerprintDetection(Detection):
    """Detect cloud storage provider by fingerprinting error page content."""

    name = "error_fingerprint_check"
    description = "Identify cloud provider from error page patterns"
    providers = [Provider.AWS, Provider.GCP, Provider.AZURE, Provider.GENERIC]
    confidence = Confidence.MEDIUM

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            # Request a path that is unlikely to exist to trigger an error page
            url = f'https://{domain}/{UNIQUE_FILENAME}_nonexistent'
            r = requests.get(url, verify=False, timeout=10)
            content = r.content.decode('utf-8', errors='replace')

            for pattern, provider, description in ERROR_PATTERNS:
                if pattern.search(content):
                    return self._success(
                        provider=provider,
                        message=f"Error page fingerprint matches {provider.value}: {description}",
                    )

            return self._failure("No cloud storage error fingerprint matched")

        except Exception as e:
            return self._failure(f"Error fingerprint check failed: {e}")
