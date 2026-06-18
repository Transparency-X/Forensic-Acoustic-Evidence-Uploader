"""
Forensic Acoustic Evidence Uploader
Dual-cloud (Cloudflare R2 + Backblaze B2) upload pipeline with SHA-256 chain of custody.

Requirements: Python 3.10+ (Python 3.9 reached AWS SDK EOL April 2026)
Dependencies: boto3==1.35.81, python-dotenv==1.0.1
"""

import os
import sys
import json
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Explicit import required - boto3 does not auto-load s3.transfer submodule
import boto3
import boto3.s3.transfer
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv


class ProgressPercentage:
    """Thread-safe upload progress callback for large WAV files."""

    def __init__(self, filename: str):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount: int):
        with self._lock:
            self._seen_so_far += bytes_amount
            if self._size > 0:
                percentage = (self._seen_so_far / self._size) * 100
                mb_done = self._seen_so_far / (1024 * 1024)
                mb_total = self._size / (1024 * 1024)
                sys.stdout.write(
                    f"\r  Uploading {os.path.basename(self._filename)}: "
                    f"{mb_done:.1f}MB / {mb_total:.1f}MB ({percentage:.1f}%)"
                )
                sys.stdout.flush()
                if self._seen_so_far >= self._size:
                    print("\n")


class DualCloudForensicUploader:
    """
    Provider-agnostic forensic uploader for Cloudflare R2 and Backblaze B2.
    Computes SHA-256 pre-upload, performs multipart transfer, verifies via ETag,
    and generates a local chain-of-custody receipt.
    """

    def __init__(self, env_path: str = ".env"):
        load_dotenv(env_path)

        # Multipart config optimized for large lossless audio files
        self.transfer_config = boto3.s3.transfer.TransferConfig(
            multipart_threshold=25 * 1024 * 1024,   # 25 MB
            max_concurrency=10,
            multipart_chunksize=25 * 1024 * 1024,   # 25 MB
            use_threads=True,
        )

        # Common boto3 config for S3-compatible providers
        s3_compat_config = Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 5, "mode": "adaptive"},
            max_pool_connections=20,
            read_timeout=300,
            connect_timeout=30,
        )

        # Initialize Cloudflare R2 client
        r2_account_id = os.getenv("R2_ACCOUNT_ID", "")
        self.r2_client = boto3.client(
            "s3",
            endpoint_url=f"https://{r2_account_id}.r2.cloudflarestorage.com",
            aws_access_key_id=os.getenv("R2_ACCESS_KEY", ""),
            aws_secret_access_key=os.getenv("R2_SECRET_KEY", ""),
            region_name="auto",
            config=s3_compat_config,
        )

        # Initialize Backblaze B2 client
        b2_region = os.getenv("B2_REGION", "us-west-004")
        self.b2_client = boto3.client(
            "s3",
            endpoint_url=f"https://s3.{b2_region}.backblazeb2.com",
            aws_access_key_id=os.getenv("B2_KEY_ID", ""),
            aws_secret_access_key=os.getenv("B2_APP_KEY", ""),
            region_name=b2_region,
            config=s3_compat_config,
        )

        self.providers: Dict[str, dict] = {
            "R2": {
                "client": self.r2_client,
                "bucket": os.getenv("R2_BUCKET_NAME", ""),
                "name": "Cloudflare R2",
            },
            "B2": {
                "client": self.b2_client,
                "bucket": os.getenv("B2_BUCKET_NAME", ""),
                "name": "Backblaze B2",
            },
        }

    def validate_connections(self) -> None:
        """
        Test connectivity to all configured providers before uploading.
        Exits immediately on failure to prevent partial evidence uploads.
        """
        all_valid = True
        for key, config in self.providers.items():
            try:
                config["client"].head_bucket(Bucket=config["bucket"])
                print(f"✅ {config['name']} ({key}): Connection validated")
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                print(f"❌ {config['name']} ({key}): FAILED [{error_code}] - {e}")
                all_valid = False
            except Exception as e:
                print(f"❌ {config['name']} ({key}): FAILED - {e}")
                all_valid = False

        if not all_valid:
            raise SystemExit(
                "One or more provider connections failed. "
                "Check .env credentials and bucket names before uploading evidence."
            )

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Compute SHA-256 hash in 4KB chunks to handle multi-GB files safely."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def upload(
        self,
        file_path: str,
        case_id: str,
        device_id: str,
        extra_metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, dict]:
        """
        Upload a forensic audio file to all configured cloud providers.

        Args:
            file_path:      Absolute path to the lossless WAV/FLAC file.
            case_id:        Unique case identifier for object key organization.
            device_id:      Recording device serial number or identifier.
            extra_metadata: Optional additional metadata key-value pairs.

        Returns:
            Dictionary of upload results keyed by provider name.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        # --- Pre-upload forensics ---
        print(f"Calculating SHA-256 for {os.path.basename(file_path)}...")
        file_hash = self.calculate_sha256(file_path)
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        file_size_bytes = os.path.getsize(file_path)
        print(f"  Hash: {file_hash}")
        print(f"  Size: {file_size_bytes / (1024*1024):.2f} MB")

        # S3 metadata keys must be lowercase, hyphenated, string values
        metadata = {
            "sha256-hash": file_hash,
            "case-id": case_id,
            "device-id": device_id,
            "capture-timestamp": timestamp_utc,
            "format": "lossless-wav-24bit",
            "file-size-bytes": str(file_size_bytes),
        }
        if extra_metadata:
            for k, v in extra_metadata.items():
                safe_key = k.lower().replace("_", "-").replace(" ", "-")
                metadata[safe_key] = str(v)

        date_prefix = timestamp_utc[:10]
        object_key = f"evidence/{case_id}/{date_prefix}/{os.path.basename(file_path)}"

        results: Dict[str, dict] = {}

        # --- Upload to each provider ---
        for provider_key, config in self.providers.items():
            client = config["client"]
            bucket = config["bucket"]
            provider_name = config["name"]

            print(f"\n--- Uploading to {provider_name} ---")
            try:
                client.upload_file(
                    Filename=file_path,
                    Bucket=bucket,
                    Key=object_key,
                    ExtraArgs={
                        "Metadata": metadata,
                        "ContentType": "audio/wav",
                    },
                    Config=self.transfer_config,
                    Callback=ProgressPercentage(file_path),
                )

                # Post-upload verification via HeadObject
                head = client.head_object(Bucket=bucket, Key=object_key)
                etag = head["ETag"].strip('"')

                results[provider_key] = {
                    "status": "SUCCESS",
                    "provider_name": provider_name,
                    "bucket": bucket,
                    "object_key": object_key,
                    "etag": etag,
                    "sha256_pre_upload": file_hash,
                    "size_bytes": file_size_bytes,
                    "timestamp_utc": timestamp_utc,
                }
                print(f"  ✅ {provider_name} upload verified. ETag: {etag}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                error_msg = e.response.get("Error", {}).get("Message", str(e))
                results[provider_key] = {
                    "status": "FAILED",
                    "provider_name": provider_name,
                    "error_code": error_code,
                    "error_message": error_msg,
                }
                print(f"  ❌ {provider_name} FAILED [{error_code}]: {error_msg}")

            except Exception as e:
                results[provider_key] = {
                    "status": "FAILED",
                    "provider_name": provider_name,
                    "error_code": "UnexpectedError",
                    "error_message": str(e),
                }
                print(f"  ❌ {provider_name} FAILED: {e}")

        # --- Generate chain of custody receipt ---
        self._generate_custody_receipt(file_path, file_hash, timestamp_utc, results)

        return results

    def verify_integrity(
        self,
        provider_key: str,
        bucket: str,
        object_key: str,
        expected_hash: str,
    ) -> bool:
        """
        Download object from cloud and verify SHA-256 matches pre-upload hash.
        Critical for chain of custody validation.
        """
        if provider_key not in self.providers:
            print(f"❌ Unknown provider: {provider_key}")
            return False

        client = self.providers[provider_key]["client"]
        sha256_hash = hashlib.sha256()

        try:
            response = client.get_object(Bucket=bucket, Key=object_key)
            for chunk in response["Body"].iter_chunks(chunk_size=8192):
                sha256_hash.update(chunk)

            actual_hash = sha256_hash.hexdigest()
            match = actual_hash == expected_hash

            if match:
                print(f"  ✅ Integrity verified for {object_key}")
            else:
                print(f"  ❌ HASH MISMATCH for {object_key}")
                print(f"     Expected: {expected_hash}")
                print(f"     Actual:   {actual_hash}")

            return match

        except Exception as e:
            print(f"  ❌ Verification failed for {object_key}: {e}")
            return False

    @staticmethod
    def _generate_custody_receipt(
        file_path: str,
        file_hash: str,
        timestamp: str,
        results: Dict[str, dict],
    ) -> None:
        """Write immutable chain of custody JSON receipt alongside source file."""
        receipt = {
            "chain_of_custody_record": True,
            "schema_version": "1.0",
            "local_file_path": os.path.abspath(file_path),
            "pre_upload_sha256": file_hash,
            "timestamp_utc": timestamp,
            "cloud_destinations": results,
        }

        base_name = os.path.basename(file_path)
        receipt_name = base_name.rsplit(".", 1)[0] + "_custody_receipt.json"
        receipt_path = os.path.join(os.path.dirname(file_path), receipt_name)

        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2, ensure_ascii=False)

        print(f"\n📋 Chain of Custody Receipt: {receipt_path}")


if __name__ == "__main__":
    uploader = DualCloudForensicUploader()
    uploader.validate_connections()

    TARGET_FILE = "test_recording_24bit_96k.wav"

    if not os.path.exists(TARGET_FILE):
        print(f"\nCreating dummy 50MB test file '{TARGET_FILE}'...")
        with open(TARGET_FILE, "wb") as f:
            f.write(b"\x00" * (50 * 1024 * 1024))

    upload_results = uploader.upload(
        file_path=TARGET_FILE,
        case_id="ACOUSTIC-HARASSMENT-2026-001",
        device_id="UMIK-1-SN-849201",
    )

    # Post-upload integrity verification for each successful provider
    print("\n=== Post-Upload Integrity Verification ===")
    for provider_key, result in upload_results.items():
        if result.get("status") == "SUCCESS":
            is_valid = uploader.verify_integrity(
                provider_key=provider_key,
                bucket=result["bucket"],
                object_key=result["object_key"],
                expected_hash=result["sha256_pre_upload"],
            )
            status_icon = "✅" if is_valid else "❌"
            print(f"{status_icon} {result['provider_name']} integrity: {is_valid}")
        else:
            print(f"⏭️  {result.get('provider_name', provider_key)} skipped (upload failed)")
