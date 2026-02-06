"""Command-line interface for bucket-decloaker."""

import argparse
import sys

import tldextract

from bucket_decloaker.engine import DetectionEngine
from bucket_decloaker.output import print_results, write_json


def main(args=None):
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Decloak a domain potentially using a bucket or blob storage.'
    )
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='The domain containing a bucket or blob storage to be "discovered".'
    )
    parser.add_argument(
        '-o', '--output',
        required=False,
        help='Output file to write the results to (JSON format).'
    )
    parser.add_argument(
        '--aws-key',
        required=False,
        help='Pass a valid AWS key (AKIA...) to perform some specific checks that require a valid key.'
    )
    parser.add_argument(
        '--list-detections',
        action='store_true',
        help='List all available detection modules and exit.'
    )

    parsed_args = parser.parse_args(args)

    # Initialize detection engine
    engine = DetectionEngine()

    # List detections mode
    if parsed_args.list_detections:
        print("Available detections:")
        for detection in engine.list_detections():
            providers = ', '.join(detection['providers'])
            params = ', '.join(detection['requires_params']) if detection['requires_params'] else 'none'
            print(f"  - {detection['name']}")
            print(f"      Description: {detection['description']}")
            print(f"      Providers: {providers}")
            print(f"      Confidence: {detection['confidence']}")
            print(f"      Required params: {params}")
            print()
        return 0

    # Extract domain from URL
    extracted = tldextract.extract(parsed_args.domain)
    domain = ".".join(filter(None, [extracted.subdomain, extracted.domain, extracted.suffix]))

    # Build context with optional parameters
    context = {}
    if parsed_args.aws_key:
        context['aws_key'] = parsed_args.aws_key

    # Run scan
    result = engine.scan(domain, context)

    # Print results
    print_results(result)

    # Output to file if specified
    if parsed_args.output:
        write_json(result, parsed_args.output)
        print(f"[i] Results written to {parsed_args.output}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
