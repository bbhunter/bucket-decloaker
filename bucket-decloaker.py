#!/usr/bin/env python3
"""
Bucket Decloaker - Cloud storage detection tool.

This is a thin wrapper for backwards compatibility.
The main implementation is in bucket_decloaker/cli.py
"""

import sys

from bucket_decloaker.cli import main

if __name__ == '__main__':
    sys.exit(main())
