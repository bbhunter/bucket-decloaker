# bucket-decloaker
A tool to decloak/expose the bucket name behind a domain.

Implements all known techniques from:
- https://gist.github.com/fransr/a155e5bd7ab11c93923ec8ce788e3368
- https://medium.com/@localh0t/unveiling-amazon-s3-bucket-names-e1420ceaf4fa

And extends them with additional checks for AWS, GCP, Azure, DigitalOcean Spaces, Backblaze B2, Cloudflare R2, and Alibaba Cloud OSS.

# Usage

```
pip3 install -r requirements.txt
python3 bucket-decloaker.py -d example.com
```

With optional parameters:
```
python3 bucket-decloaker.py -d example.com -o results.json --aws-key AKIAIOSFODNN7EXAMPLE
```

# Detection Techniques

The tool uses a modular plugin-based architecture. Detections are auto-discovered and run in two phases: generic/multi-provider checks first, then provider-specific checks.

## Generic / Multi-Provider (8 checks)

| Check | Description | Confidence |
|-------|-------------|------------|
| **CNAME lookup** | DNS CNAME records pointing to cloud storage endpoints | HIGH |
| **HTTP headers** | `Server: AmazonS3`, `x-goog-*`, `x-ms-*` header fingerprinting | HIGH |
| **URL %C0 trick** | Trigger S3 error via `%C0` character to leak bucket name | HIGH |
| **Direct URL check** | Check if domain-named bucket exists on S3/GCP | LOW |
| **TLS certificate** | Inspect certificate SAN/CN for cloud storage patterns | MEDIUM |
| **IP range lookup** | Check resolved IP against published AWS/GCP/Azure IP ranges | LOW |
| **Error page fingerprint** | Pattern-match provider-specific error pages | MEDIUM |
| **S3-compatible check** | Check domain-named buckets on DO Spaces, Backblaze, Alibaba OSS | LOW |

## AWS S3 (7 checks)

| Check | Description | Confidence |
|-------|-------------|------------|
| **Signing error** | Trigger signing error with AWS key to extract bucket name | HIGH |
| **ACL endpoint** | `?acl` endpoint to extract owner ID or confirm S3 | HIGH |
| **Bucket region** | `x-amz-bucket-region` header discovery | HIGH |
| **SOAP endpoint** | Check for S3-specific SOAP endpoint response | HIGH |
| **Bucket listing** | Extract bucket name from XML listing response | HIGH |
| **Torrent metadata** | Extract `x-amz-bucket` from torrent file metadata | HIGH |
| **Unicode error** | Trigger error with unicode characters (experimental) | LOW |

## GCP Storage (3 checks)

| Check | Description | Confidence |
|-------|-------------|------------|
| **Signature error** | Fake `GoogleAccessId` signature to leak bucket name (HTTPS + HTTP) | HIGH |
| **Permission errors** | Extract bucket name from IAM permission error messages | HIGH |
| **alt=json trick** | `?alt=json` parameter to trigger JSON error responses | HIGH |

## Azure Blob Storage (2 checks)

| Check | Description | Confidence |
|-------|-------------|------------|
| **comp=list parameter** | Trigger Azure error via `?comp=list` to extract container name | HIGH |
| **restype=container** | Trigger Azure error via `?restype=container` | HIGH |

## Supported Providers

- Amazon Web Services (S3, CloudFront)
- Google Cloud Platform (Cloud Storage)
- Microsoft Azure (Blob Storage, CDN)
- DigitalOcean Spaces
- Backblaze B2
- Cloudflare R2
- Alibaba Cloud OSS

# Adding a Detection

Create a new Python file in the appropriate `bucket_decloaker/detections/<provider>/` directory:

```python
from typing import Optional, Dict, Any
from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection

class MyDetection(Detection):
    name = "my_check"
    description = "What this check does"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        # Your detection logic here
        return self._success(
            provider=Provider.AWS,
            bucket_name="found-bucket",
            message="Description of finding",
        )
```

The detection will be auto-discovered — no registration needed.

# Disclaimer

I suck at coding, so feel free to insult me or to completely refactor this piece of cr\*p.
