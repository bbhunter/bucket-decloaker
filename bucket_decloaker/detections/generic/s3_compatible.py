"""S3-compatible provider detection for DigitalOcean Spaces, Backblaze B2, Cloudflare R2, and Alibaba OSS."""

from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# S3-compatible provider endpoints to check
# (url_template, not_found_text, provider, label)
S3_COMPAT_CHECKS = [
    # DigitalOcean Spaces — buckets are region-scoped
    ('https://{domain}.ams3.digitaloceanspaces.com', Provider.DIGITALOCEAN, 'DigitalOcean Spaces (ams3)'),
    ('https://{domain}.nyc3.digitaloceanspaces.com', Provider.DIGITALOCEAN, 'DigitalOcean Spaces (nyc3)'),
    ('https://{domain}.sfo3.digitaloceanspaces.com', Provider.DIGITALOCEAN, 'DigitalOcean Spaces (sfo3)'),
    ('https://{domain}.sgp1.digitaloceanspaces.com', Provider.DIGITALOCEAN, 'DigitalOcean Spaces (sgp1)'),
    ('https://{domain}.fra1.digitaloceanspaces.com', Provider.DIGITALOCEAN, 'DigitalOcean Spaces (fra1)'),
    ('https://{domain}.syd1.digitaloceanspaces.com', Provider.DIGITALOCEAN, 'DigitalOcean Spaces (syd1)'),
    # Backblaze B2 — S3-compatible endpoint
    ('https://{domain}.s3.us-west-004.backblazeb2.com', Provider.BACKBLAZE, 'Backblaze B2 (us-west-004)'),
    ('https://{domain}.s3.us-west-002.backblazeb2.com', Provider.BACKBLAZE, 'Backblaze B2 (us-west-002)'),
    ('https://{domain}.s3.eu-central-003.backblazeb2.com', Provider.BACKBLAZE, 'Backblaze B2 (eu-central-003)'),
    # Alibaba Cloud OSS
    ('https://{domain}.oss-cn-hangzhou.aliyuncs.com', Provider.ALIBABA, 'Alibaba OSS (cn-hangzhou)'),
    ('https://{domain}.oss-us-west-1.aliyuncs.com', Provider.ALIBABA, 'Alibaba OSS (us-west-1)'),
    ('https://{domain}.oss-eu-central-1.aliyuncs.com', Provider.ALIBABA, 'Alibaba OSS (eu-central-1)'),
    ('https://{domain}.oss-ap-southeast-1.aliyuncs.com', Provider.ALIBABA, 'Alibaba OSS (ap-southeast-1)'),
]


class S3CompatibleDetection(Detection):
    """Check if domain-named bucket exists on S3-compatible providers."""

    name = "s3_compatible_check"
    description = "Check if domain-named bucket exists on DigitalOcean, Backblaze, Cloudflare R2, or Alibaba"
    providers = [Provider.DIGITALOCEAN, Provider.BACKBLAZE, Provider.CLOUDFLARE, Provider.ALIBABA, Provider.GENERIC]
    confidence = Confidence.LOW

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        not_found_indicators = [
            b'NoSuchBucket',
            b'The specified bucket does not exist',
            b'bucket does not exist',
        ]

        for url_template, provider, label in S3_COMPAT_CHECKS:
            try:
                url = url_template.format(domain=domain)
                r = requests.get(url, verify=False, timeout=8)

                # If none of the "not found" indicators are present, bucket likely exists
                if not any(ind in r.content for ind in not_found_indicators):
                    return self._success(
                        provider=provider,
                        bucket_name=domain,
                        confidence=Confidence.LOW,
                        message=f"Bucket exists on {label}: {domain}",
                    )
            except Exception:
                continue

        return self._failure("No bucket found on S3-compatible providers")
