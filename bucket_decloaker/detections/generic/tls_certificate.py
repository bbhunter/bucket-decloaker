"""TLS certificate inspection for cloud storage providers."""

import re
import ssl
import socket
from typing import Optional, Dict, Any

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

# Patterns to match in certificate SAN/CN fields
PROVIDER_PATTERNS = [
    (re.compile(r'\.s3\.amazonaws\.com$'), Provider.AWS, "S3"),
    (re.compile(r'\.s3[-.].*\.amazonaws\.com$'), Provider.AWS, "S3"),
    (re.compile(r'\.cloudfront\.net$'), Provider.AWS, "CloudFront"),
    (re.compile(r'\.amazonaws\.com$'), Provider.AWS, "AWS"),
    (re.compile(r'\.storage\.googleapis\.com$'), Provider.GCP, "GCP Storage"),
    (re.compile(r'\.googleapis\.com$'), Provider.GCP, "GCP"),
    (re.compile(r'\.blob\.core\.windows\.net$'), Provider.AZURE, "Azure Blob"),
    (re.compile(r'\.web\.core\.windows\.net$'), Provider.AZURE, "Azure Static Web"),
    (re.compile(r'\.azureedge\.net$'), Provider.AZURE, "Azure CDN"),
    (re.compile(r'\.azure\.com$'), Provider.AZURE, "Azure"),
    (re.compile(r'\.digitaloceanspaces\.com$'), Provider.DIGITALOCEAN, "DigitalOcean Spaces"),
    (re.compile(r'\.backblazeb2\.com$'), Provider.BACKBLAZE, "Backblaze B2"),
    (re.compile(r'\.r2\.cloudflarestorage\.com$'), Provider.CLOUDFLARE, "Cloudflare R2"),
    (re.compile(r'\.aliyuncs\.com$'), Provider.ALIBABA, "Alibaba Cloud OSS"),
]


class TLSCertificateDetection(Detection):
    """Detect cloud storage provider from TLS certificate SAN/CN entries."""

    name = "tls_certificate_check"
    description = "Inspect TLS certificate for cloud storage provider indicators"
    providers = [Provider.AWS, Provider.GCP, Provider.AZURE, Provider.DIGITALOCEAN, Provider.BACKBLAZE, Provider.CLOUDFLARE, Provider.ALIBABA, Provider.GENERIC]
    confidence = Confidence.MEDIUM

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    cert = tls_sock.getpeercert(binary_form=True)

            # Parse the DER certificate to extract SANs
            # Use ssl to get the decoded cert by connecting with verification disabled
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    cert_dict = tls_sock.getpeercert()

            if not cert_dict:
                return self._failure("Could not retrieve TLS certificate details")

            # Collect all names from the certificate
            names = set()

            # Common Name
            subject = cert_dict.get('subject', ())
            for rdn in subject:
                for attr_type, attr_value in rdn:
                    if attr_type == 'commonName':
                        names.add(attr_value.lower())

            # Subject Alternative Names
            san = cert_dict.get('subjectAltName', ())
            for san_type, san_value in san:
                if san_type == 'DNS':
                    names.add(san_value.lower())

            # Check against known patterns
            for name in names:
                for pattern, provider, service in PROVIDER_PATTERNS:
                    if pattern.search(name):
                        return self._success(
                            provider=provider,
                            message=f"TLS certificate SAN matches {service}: {name}",
                        )

            return self._failure("No cloud storage indicators in TLS certificate")

        except Exception as e:
            return self._failure(f"TLS certificate check error: {e}")
