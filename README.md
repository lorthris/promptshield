# PromptShield

Local tool to find and mask secrets, credentials, and identity data before sending text to artificial intelligence models.

## Purpose

Artificial intelligence models can record data that users send in prompts. This tool removes secrets, private keys, database addresses, and identity numbers from logs, files, and text. The tool operates locally on your computer with zero network communication.

## Capabilities

- Find credentials for OpenAI, Anthropic, Google Gemini, Amazon Web Services, GitHub, Stripe, Slack, and SendGrid.
- Find database addresses with passwords and private keys.
- Find Australian Tax File Numbers, Australian mobile numbers, credit card numbers, and electronic mail addresses.
- Calculate Shannon entropy to identify random secret strings.
- Replace identical secrets with the same token name to keep context for the model.
- Restore real values in model output by reading a local session file.
- Prevent git commits that contain unmasked secrets.
- Mask text on the system clipboard.
- Run an offline visual interface in any web browser.

## Requirements

- Python 3.8 or newer.
- Modern web browser for the visual tool.
- No external packages required. Standard library only.

## Commands

### 1. Find Secrets in a File

```powershell
python -m promptshield.cli scan path/to/file.txt
```

To get structured machine output:

```powershell
python -m promptshield.cli scan path/to/file.txt --json
```

### 2. Mask Secrets in a File

```powershell
python -m promptshield.cli redact dirty.log --out clean.log
```

To save a session for later restoration:

```powershell
python -m promptshield.cli redact dirty.log --session bug101 --out clean.log
```

### 3. Restore Secrets from a Session

```powershell
python -m promptshield.cli restore ai_answer.txt --session bug101 --out final.txt
```

### 4. Mask Clipboard Text

```powershell
python -m promptshield.cli clip
```

### 5. Install Git Pre-Commit Hook

```powershell
python -m promptshield.cli install-hook
```

## Structure

- `promptshield/`: Python package files.
- `tests/`: Automated unit tests.
- `web/`: Offline web application files.
- `distribution/`: Packaging scripts and merchant configuration.
