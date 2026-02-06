"""Torrent file detection for AWS S3."""

import tempfile
from typing import Optional, Dict, Any
import urllib.request

from bucket_decloaker.core import Provider, Confidence, DetectionResult
from bucket_decloaker.detections.base import Detection


class TorrentDetection(Detection):
    """Detect S3 bucket name from torrent file metadata."""

    name = "torrent_check"
    description = "Extract S3 bucket name from torrent file"
    providers = [Provider.AWS]
    confidence = Confidence.HIGH

    def check(self, domain: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        # This check requires a bucket name to already be known
        bucket_name = context.get('bucket_name') if context else None

        if not bucket_name:
            return self._failure("Torrent check requires known bucket name")

        try:
            import torrent_parser as tp

            url = f'http://{bucket_name}.s3.amazonaws.com/index.html?torrent'
            tmp_file, _ = urllib.request.urlretrieve(url)

            torrent_data = tp.parse_torrent_file(tmp_file)
            detected_name = torrent_data.get('info', {}).get('x-amz-bucket')

            if detected_name:
                return self._success(
                    provider=Provider.AWS,
                    bucket_name=detected_name,
                    message=f"S3 bucket confirmed via torrent: {detected_name}",
                )

            return self._failure("No bucket name found in torrent file")

        except ImportError:
            return self._failure("torrent_parser module not installed")
        except Exception as e:
            return self._failure(f"Torrent check error: {e}")
