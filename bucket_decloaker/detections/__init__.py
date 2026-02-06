"""Detection module auto-discovery and loading."""

import importlib
import pkgutil
from pathlib import Path
from typing import List, Type, Optional

from bucket_decloaker.core import Provider
from bucket_decloaker.detections.base import Detection


def discover_detections() -> List[Type[Detection]]:
    """Auto-discover all Detection subclasses in the detections package.

    Returns:
        List of Detection subclasses found in the package.
    """
    detections = []
    package_dir = Path(__file__).parent

    # Walk through all subpackages (generic, aws, gcp, azure)
    for subdir in ['generic', 'aws', 'gcp', 'azure']:
        subdir_path = package_dir / subdir
        if not subdir_path.is_dir():
            continue

        # Import all modules in the subpackage
        for module_info in pkgutil.iter_modules([str(subdir_path)]):
            if module_info.name.startswith('_'):
                continue

            module_name = f"bucket_decloaker.detections.{subdir}.{module_info.name}"
            try:
                module = importlib.import_module(module_name)

                # Find all Detection subclasses in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, Detection)
                        and attr is not Detection
                        and attr.name  # Has a name set
                    ):
                        detections.append(attr)
            except ImportError as e:
                print(f"[!] Failed to import detection module {module_name}: {e}")

    return detections


def get_detections_for_provider(
    provider: Optional[Provider],
    detections: Optional[List[Type[Detection]]] = None,
) -> List[Type[Detection]]:
    """Filter detections by provider.

    Args:
        provider: Provider to filter by, or None for generic detections
        detections: List of detections to filter, or None to discover all

    Returns:
        List of Detection subclasses that match the provider
    """
    if detections is None:
        detections = discover_detections()

    if provider is None:
        # Return generic detections (those that apply to multiple providers)
        return [d for d in detections if Provider.GENERIC in d.providers or len(d.providers) > 1]

    return [d for d in detections if provider in d.providers]


def get_generic_detections(
    detections: Optional[List[Type[Detection]]] = None,
) -> List[Type[Detection]]:
    """Get detections that work across multiple providers.

    Args:
        detections: List of detections to filter, or None to discover all

    Returns:
        List of Detection subclasses for generic/multi-provider checks
    """
    if detections is None:
        detections = discover_detections()

    return [d for d in detections if Provider.GENERIC in d.providers or len(d.providers) > 1]


def get_provider_specific_detections(
    provider: Provider,
    detections: Optional[List[Type[Detection]]] = None,
) -> List[Type[Detection]]:
    """Get detections specific to a single provider.

    Args:
        provider: The provider to get detections for
        detections: List of detections to filter, or None to discover all

    Returns:
        List of Detection subclasses specific to that provider
    """
    if detections is None:
        detections = discover_detections()

    return [
        d for d in detections
        if provider in d.providers and len(d.providers) == 1
    ]
