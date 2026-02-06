"""Core types and utilities for bucket-decloaker."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class Provider(Enum):
    """Cloud storage provider."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    GENERIC = "generic"


class Confidence(Enum):
    """Confidence level for detection results."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class DetectionResult:
    """Immutable result from a single detection check."""
    detection_name: str
    success: bool
    provider: Optional[Provider] = None
    bucket_name: Optional[str] = None
    load_balancer: Optional[bool] = None
    load_balancer_name: Optional[str] = None
    confidence: Confidence = Confidence.MEDIUM
    message: Optional[str] = None


@dataclass
class ScanResult:
    """Aggregated results from all detection checks."""
    domain: str
    provider: Optional[Provider] = None
    bucket_name: Optional[str] = None
    load_balancer: Optional[bool] = None
    load_balancer_name: Optional[str] = None
    certain: bool = True
    detection_results: List[DetectionResult] = field(default_factory=list)
    checks_run: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "provider": self.provider.value if self.provider else None,
            "bucket_name": self.bucket_name,
            "load_balancer": self.load_balancer,
            "load_balancer_name": self.load_balancer_name,
            "certain": self.certain,
            "checks_run": self.checks_run,
            "detection_results": [
                {
                    "detection_name": r.detection_name,
                    "success": r.success,
                    "provider": r.provider.value if r.provider else None,
                    "bucket_name": r.bucket_name,
                    "confidence": r.confidence.value,
                    "message": r.message,
                }
                for r in self.detection_results
                if r.success
            ],
        }


class bcolors:
    """Terminal color codes."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Unique filename used for various checks
UNIQUE_FILENAME = "bucket_decloaker_01100010"
