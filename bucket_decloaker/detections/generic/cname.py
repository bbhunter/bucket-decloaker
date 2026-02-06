"""CNAME record detection for cloud storage providers."""

import re
from typing import Optional, Dict, Any

import dns.resolver

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection


class CNAMEDetection(Detection):
    """Detect cloud storage provider from CNAME records."""

    name = "cname_check"
    description = "Check CNAME records for cloud storage provider indicators"
    providers = [Provider.AWS, Provider.GCP, Provider.AZURE, Provider.GENERIC]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                target = str(rdata.target).rstrip('.')

                # AWS - Cloudfront CDN
                if "cloudfront.net" in target:
                    return self._success(
                        provider=Provider.AWS,
                        load_balancer=True,
                        load_balancer_name=target,
                        message=f"CNAME points to CloudFront: {target}",
                    )

                # AWS - Direct S3
                s3_pattern = re.compile(r".*s3.*\.amazonaws\.com")
                if s3_pattern.search(target):
                    return self._success(
                        provider=Provider.AWS,
                        load_balancer=False,
                        load_balancer_name=target,
                        message=f"CNAME points to S3: {target}",
                    )

                # GCP - Storage bucket
                gcp_pattern = re.compile(r".*\.storage\.googleapis\.com")
                if gcp_pattern.search(target):
                    return self._success(
                        provider=Provider.GCP,
                        bucket_name=domain,
                        message=f"CNAME points to GCP Storage: {target}",
                    )

                # Azure - CDN (azureedge)
                if "azureedge.net" in target:
                    return self._success(
                        provider=Provider.AZURE,
                        load_balancer=True,
                        load_balancer_name=target,
                        message=f"CNAME points to Azure CDN: {target}",
                    )

                # Azure - Blob storage
                azure_pattern = re.compile(r".*\.(web|blob)\.core\.windows\.net")
                if azure_pattern.search(target):
                    return self._success(
                        provider=Provider.AZURE,
                        bucket_name=domain,
                        message=f"CNAME points to Azure Blob: {target}",
                    )

            return self._failure("No cloud storage CNAME found")

        except dns.resolver.NoAnswer:
            return self._failure("No CNAME record found")
        except dns.resolver.NXDOMAIN:
            return self._failure("Domain does not exist")
        except Exception as e:
            return self._failure(f"CNAME check error: {e}")
