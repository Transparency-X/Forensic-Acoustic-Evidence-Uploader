# Forensic Acoustic Evidence Uploader

A dual-cloud forensic upload pipeline for high-fidelity acoustic evidence. Captures lossless audio from UMIK-1 microphones, computes SHA-256 chain-of-custody hashes, and simultaneously uploads to Cloudflare R2 (zero-egress processing) and Backblaze B2 (low-cost archival).

## Architecture

```text
UMIK-1 → Local WAV (24-bit/96kHz) → SHA-256 Hash → Dual Upload
                                          ├── Cloudflare R2 (Hot / Analysis)
                                          └── Backblaze B2  (Cold / Archive)
                                                ↓
                                      Chain of Custody Receipt (JSON)
```

## Prerequisites

-   Python **3.10+** (Python 3.9 reached AWS SDK end-of-support April 2026)
-   Cloudflare R2 bucket with Account API Token (`Object Read & Write`)
-   Backblaze B2 bucket with Application Key (`Read and Write`)
-   UMIK-1 calibrated USB microphone (optional, for capture workflow)

## Installation

### 1. Clone and Create Virtual Environment

```bash
git clone https://github.com/your-org/forensic-acoustic-uploader.git
cd forensic-acoustic-uploader

python3.10 -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .\.venv\Scripts\Activate.ps1  # Windows PowerShell
```

> ⚠️ **Never install dependencies globally.** Always verify `(.venv)` appears in your prompt.

### 2. Install Pinned Dependencies

```bash
pip install boto3==1.35.81 python-dotenv==1.0.1
pip freeze > requirements.txt
```

### 3. Configure Credentials

Create a `.env` file in the project root:

```ini
# === CLOUDFLARE R2 (Use ACCOUNT API TOKEN, not User Token) ===
R2_ACCOUNT_ID=your_account_id
R2_ACCESS_KEY=your_32_char_r2_account_access_key
R2_SECRET_KEY=your_r2_account_secret_key
R2_BUCKET_NAME=acoustic-evidence-r2

# === BACKBLAZE B2 ===
B2_REGION=us-west-004
B2_KEY_ID=your_b2_key_id
B2_APP_KEY=your_b2_application_key
B2_BUCKET_NAME=acoustic-evidence-b2
```

Lock down permissions:

```bash
chmod 600 .env
echo ".env" >> .gitignore
```

### 4. Validate Connectivity

```python
from forensic_uploader import DualCloudForensicUploader

uploader = DualCloudForensicUploader()
uploader.validate_connections()
# Expected: ✅ R2: Connection validated
# Expected: ✅ B2: Connection validated
```

## Usage

### Single File Upload

```python
from forensic_uploader import DualCloudForensicUploader

uploader = DualCloudForensicUploader()
result = uploader.upload(
    file_path="/evidence/2026-06-19_apt4b_night.wav",
    case_id="CASE-2026-0042",
    device_id="UMIK-1-SN-7024589"
)
```

### Verify Chain of Custody

```python
is_valid = uploader.verify_integrity(
    provider_key="R2",
    bucket="acoustic-evidence-r2",
    object_key=result["R2"]["object_key"],
    expected_hash=result["R2"]["sha256_pre_upload"]
)
assert is_valid, "CHAIN OF CUSTODY BROKEN"
```

Each upload generates a `_custody_receipt.json` alongside the source file containing pre-upload SHA-256, timestamps, and cloud ETags.

## Cloudflare R2 Token Guide

| Token Type | Use For | Forensic Pipeline? |
| :--- | :--- | :--- |
| **Account API Token** | Production systems, service auth, persists after user departure | ✅ **YES** |
| User API Token | Personal dev, temporary access, expires when user leaves org | ❌ NO |

**Required Permission:** `Object Read & Write` scoped to your specific evidence bucket only.

## Troubleshooting

| Error | Cause | Fix |
| :--- | :--- | :--- |
| `Credential access key has length 53, should be 32` | Using Global/User API token instead of R2 S3 token | Generate new **Account API Token** under R2 → Manage API Tokens |
| `module 'boto3' has no attribute 's3'` | Missing explicit submodule import | Add `import boto3.s3.transfer` to imports |
| `PythonDeprecationWarning: Python 3.9` | AWS SDK dropped 3.9 support April 2026 | Recreate venv with `python3.10 -m venv .venv` |
| `InvalidAccessKeyId` | Wrong endpoint URL or wrong token type | Verify endpoint matches `https://{ACCOUNT_ID}.r2.cloudflarestorage.com` |
| Upload hangs at 99% | Multipart completion timeout | Increase `max_concurrency` to 15 in TransferConfig |

## Security Notes

-   SHA-256 is computed in 4KB chunks — safe for multi-GB files
-   Credentials are never logged; only filenames, sizes, and ETags appear in output
-   Rotate R2 and B2 keys quarterly
-   Store custody receipts separately from audio files
-   For air-gapped cases, add MinIO as a third provider via config (no code changes)

## License

MIT
