"""Base class for all detection modules."""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from bucket_decloaker.core import Provider, Confidence, DetectionResult


class Detection(ABC):
    """Abstract base class for detection modules.

    To create a new detection, subclass this and implement:
    - name: A unique identifier for this detection
    - description: Human-readable description of what it detects
    - providers: List of providers this detection applies to
    - check(): The detection logic
    """

    name: str = ""
    description: str = ""
    providers: List[Provider] = []
    confidence: Confidence = Confidence.MEDIUM
    requires_params: List[str] = []

    @abstractmethod
    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """Run the detection check.

        Args:
            domain: The domain to check
            context: Optional context dict with params like aws_key, current scan state, etc.

        Returns:
            DetectionResult with detection outcome
        """
        pass

    def _success(
        self,
        provider: Optional[Provider] = None,
        bucket_name: Optional[str] = None,
        load_balancer: Optional[bool] = None,
        load_balancer_name: Optional[str] = None,
        confidence: Optional[Confidence] = None,
        message: Optional[str] = None,
    ) -> DetectionResult:
        """Helper to create a successful detection result."""
        return DetectionResult(
            detection_name=self.name,
            success=True,
            provider=provider,
            bucket_name=bucket_name,
            load_balancer=load_balancer,
            load_balancer_name=load_balancer_name,
            confidence=confidence or self.confidence,
            message=message,
        )

    def _failure(self, message: Optional[str] = None) -> DetectionResult:
        """Helper to create a failed detection result."""
        return DetectionResult(
            detection_name=self.name,
            success=False,
            message=message,
        )
