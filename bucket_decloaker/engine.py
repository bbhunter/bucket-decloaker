"""Detection engine that orchestrates all detection checks."""

from typing import Dict, Any, Optional, List, Type

from bucket_decloaker.core import Provider, Confidence, ScanResult, DetectionResult
from bucket_decloaker.detections import (
    discover_detections,
    get_generic_detections,
    get_provider_specific_detections,
)
from bucket_decloaker.detections.base import Detection


class DetectionEngine:
    """Orchestrates detection checks and aggregates results."""

    def __init__(self):
        """Initialize the engine and discover all available detections."""
        self.all_detections = discover_detections()
        self._detection_instances: Dict[str, Detection] = {}

        # Instantiate all detections
        for detection_cls in self.all_detections:
            instance = detection_cls()
            self._detection_instances[instance.name] = instance

    def _get_instance(self, detection_cls: Type[Detection]) -> Detection:
        """Get or create an instance of a detection class."""
        name = detection_cls.name
        if name not in self._detection_instances:
            self._detection_instances[name] = detection_cls()
        return self._detection_instances[name]

    def scan(self, domain: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Run all applicable detection checks on a domain.

        Args:
            domain: The domain to scan
            context: Optional context with params like aws_key

        Returns:
            ScanResult with aggregated findings
        """
        context = context or {}
        result = ScanResult(domain=domain)

        # Phase 1: Run generic/multi-provider checks
        print("[i] Running generic and/or multiple vendor checks to find out provider...")
        generic_detections = get_generic_detections(self.all_detections)
        self._run_detections(generic_detections, domain, context, result)

        # Phase 2: Run provider-specific checks based on detected provider
        providers_to_check = self._determine_providers_to_check(result)

        for provider in providers_to_check:
            print(f"[{provider.value}] Running {provider.value} specific checks...")
            provider_detections = get_provider_specific_detections(provider, self.all_detections)

            # Update context with current bucket_name for checks that need it
            check_context = context.copy()
            if result.bucket_name:
                check_context['bucket_name'] = result.bucket_name

            # Handle checks requiring parameters
            if provider == Provider.AWS:
                self._run_aws_checks(provider_detections, domain, check_context, result)
            else:
                self._run_detections(provider_detections, domain, check_context, result)

            if provider == Provider.AZURE:
                print("[i] I need more Azure checks...")

        return result

    def _run_detections(
        self,
        detection_classes: List[Type[Detection]],
        domain: str,
        context: Dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Run a list of detections and update the result."""
        for detection_cls in detection_classes:
            detection = self._get_instance(detection_cls)

            # Skip if required params are missing
            if detection.requires_params:
                missing = [p for p in detection.requires_params if not context.get(p)]
                if missing:
                    continue

            detection_result = detection.check(domain, context)
            result.checks_run.append(detection.name)
            result.detection_results.append(detection_result)

            if detection_result.success:
                self._merge_result(result, detection_result)

    def _run_aws_checks(
        self,
        detection_classes: List[Type[Detection]],
        domain: str,
        context: Dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Run AWS-specific checks, handling parameter requirements."""
        from bucket_decloaker.core import bcolors

        aws_key = context.get('aws_key')
        key_required_checks = []

        for detection_cls in detection_classes:
            detection = self._get_instance(detection_cls)

            if 'aws_key' in detection.requires_params:
                if aws_key:
                    detection_result = detection.check(domain, context)
                    result.checks_run.append(detection.name)
                    result.detection_results.append(detection_result)
                    if detection_result.success:
                        self._merge_result(result, detection_result)
                else:
                    key_required_checks.append(detection.name)
            else:
                detection_result = detection.check(domain, context)
                result.checks_run.append(detection.name)
                result.detection_results.append(detection_result)
                if detection_result.success:
                    self._merge_result(result, detection_result)

        if key_required_checks and not aws_key:
            print(bcolors.WARNING + "[i] A valid AWS key is required to perform further checks." + bcolors.ENDC)

    def _determine_providers_to_check(self, result: ScanResult) -> List[Provider]:
        """Determine which providers to run specific checks for."""
        # If provider is known with certainty, only check that provider
        if result.provider and result.certain:
            return [result.provider]

        # If provider is detected but uncertain, check that provider plus others
        all_providers = [
            Provider.AWS, Provider.GCP, Provider.AZURE,
            Provider.DIGITALOCEAN, Provider.BACKBLAZE, Provider.CLOUDFLARE, Provider.ALIBABA,
        ]
        if result.provider:
            providers = [result.provider]
            for p in all_providers:
                if p not in providers:
                    providers.append(p)
            return providers

        # No provider detected - check all
        return all_providers

    def _merge_result(self, scan_result: ScanResult, detection_result: DetectionResult) -> None:
        """Merge a detection result into the scan result."""
        # Update provider if detected
        if detection_result.provider:
            # Prefer higher confidence results
            if scan_result.provider is None:
                scan_result.provider = detection_result.provider
            elif detection_result.confidence == Confidence.HIGH:
                scan_result.provider = detection_result.provider

        # Update bucket name if found
        if detection_result.bucket_name:
            if scan_result.bucket_name is None:
                scan_result.bucket_name = detection_result.bucket_name
            elif detection_result.confidence == Confidence.HIGH:
                scan_result.bucket_name = detection_result.bucket_name

        # Update load balancer info
        if detection_result.load_balancer is not None:
            scan_result.load_balancer = detection_result.load_balancer
        if detection_result.load_balancer_name:
            scan_result.load_balancer_name = detection_result.load_balancer_name

        # Update certainty - low confidence makes result uncertain
        if detection_result.confidence == Confidence.LOW:
            scan_result.certain = False

        # Print detection messages
        if detection_result.message and detection_result.success:
            print(f'[!] {detection_result.message}')

    def list_detections(self) -> List[Dict[str, Any]]:
        """List all available detections with their metadata."""
        return [
            {
                "name": d.name,
                "description": d.description,
                "providers": [p.value for p in d.providers],
                "confidence": d.confidence.value,
                "requires_params": d.requires_params,
            }
            for d in self._detection_instances.values()
        ]
