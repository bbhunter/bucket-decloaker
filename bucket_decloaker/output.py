"""Output formatting for scan results."""

import json
from typing import Optional

from bucket_decloaker.core import ScanResult, bcolors


def print_results(result: ScanResult) -> None:
    """Print scan results to terminal with colors."""
    if result.provider is not None:
        print(bcolors.OKGREEN + f'[{result.provider.value}] Provider detected: {result.provider.value}' + bcolors.ENDC)
    else:
        print(bcolors.WARNING + '[?] Provider not fingerprinted.' + bcolors.ENDC)

    if result.bucket_name is not None:
        provider_tag = result.provider.value if result.provider else '?'
        print(bcolors.OKGREEN + f'[{provider_tag}] Bucket/blob storage detected: {result.bucket_name}' + bcolors.ENDC)
    else:
        print(bcolors.WARNING + '[?] Bucket/blob storage name not found.' + bcolors.ENDC)

    if result.certain is False:
        print(bcolors.FAIL + '[?] The results are not certain (obtained using methods that do not guarantee that the '
                           'bucket behind the domain is the one you intend to find).' + bcolors.ENDC)

    if result.provider is None and result.bucket_name is None:
        print("[i] Unknown provider / No provider found")


def to_json(result: ScanResult, pretty: bool = True) -> str:
    """Convert scan result to JSON string."""
    data = result.to_dict()
    if pretty:
        return json.dumps(data, sort_keys=True, indent=4)
    return json.dumps(data)


def write_json(result: ScanResult, filepath: str) -> None:
    """Write scan result to JSON file."""
    with open(filepath, 'w') as f:
        f.write(to_json(result))
