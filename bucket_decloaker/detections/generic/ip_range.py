"""IP range lookup detection for cloud storage providers."""

import ipaddress
import json
import socket
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Well-known IP range endpoints
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
AZURE_IP_RANGES_URL = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20250317.json"


class IPRangeDetection(Detection):
    """Detect cloud storage provider by checking if resolved IP falls within known cloud IP ranges."""

    name = "ip_range_check"
    description = "Check if domain IP belongs to known cloud provider IP ranges"
    providers = [Provider.AWS, Provider.GCP, Provider.AZURE, Provider.DIGITALOCEAN, Provider.BACKBLAZE, Provider.CLOUDFLARE, Provider.ALIBABA, Provider.GENERIC]
    confidence = Confidence.LOW

    _aws_prefixes = None
    _gcp_prefixes = None
    _azure_prefixes = None

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        try:
            ip = socket.gethostbyname(domain)
            addr = ipaddress.ip_address(ip)
        except Exception as e:
            return self._failure(f"Could not resolve domain: {e}")

        # Check AWS
        provider, service = self._check_aws(addr)
        if provider:
            return self._success(
                provider=Provider.AWS,
                confidence=Confidence.LOW,
                message=f"IP {ip} belongs to AWS ({service})",
            )

        # Check GCP
        provider, service = self._check_gcp(addr)
        if provider:
            return self._success(
                provider=Provider.GCP,
                confidence=Confidence.LOW,
                message=f"IP {ip} belongs to GCP ({service})",
            )

        # Check Azure
        provider, service = self._check_azure(addr)
        if provider:
            return self._success(
                provider=Provider.AZURE,
                confidence=Confidence.LOW,
                message=f"IP {ip} belongs to Azure ({service})",
            )

        return self._failure(f"IP {ip} does not match known cloud provider ranges")

    def _fetch_json(self, url, timeout=15):
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def _check_aws(self, addr):
        if IPRangeDetection._aws_prefixes is None:
            data = self._fetch_json(AWS_IP_RANGES_URL)
            if data:
                IPRangeDetection._aws_prefixes = [
                    (ipaddress.ip_network(p['ip_prefix']), p.get('service', 'AMAZON'))
                    for p in data.get('prefixes', [])
                ]
            else:
                IPRangeDetection._aws_prefixes = []

        for network, service in IPRangeDetection._aws_prefixes:
            if addr in network:
                return True, service
        return False, None

    def _check_gcp(self, addr):
        if IPRangeDetection._gcp_prefixes is None:
            data = self._fetch_json(GCP_IP_RANGES_URL)
            if data:
                IPRangeDetection._gcp_prefixes = []
                for p in data.get('prefixes', []):
                    prefix = p.get('ipv4Prefix') or p.get('ipv6Prefix')
                    if prefix:
                        IPRangeDetection._gcp_prefixes.append(
                            (ipaddress.ip_network(prefix), p.get('service', 'Google Cloud'))
                        )
            else:
                IPRangeDetection._gcp_prefixes = []

        for network, service in IPRangeDetection._gcp_prefixes:
            if addr in network:
                return True, service
        return False, None

    def _check_azure(self, addr):
        if IPRangeDetection._azure_prefixes is None:
            data = self._fetch_json(AZURE_IP_RANGES_URL)
            if data:
                IPRangeDetection._azure_prefixes = []
                for value in data.get('values', []):
                    name = value.get('name', 'Azure')
                    for prefix in value.get('properties', {}).get('addressPrefixes', []):
                        try:
                            IPRangeDetection._azure_prefixes.append(
                                (ipaddress.ip_network(prefix), name)
                            )
                        except ValueError:
                            continue
            else:
                IPRangeDetection._azure_prefixes = []

        for network, service in IPRangeDetection._azure_prefixes:
            if addr in network:
                return True, service
        return False, None
