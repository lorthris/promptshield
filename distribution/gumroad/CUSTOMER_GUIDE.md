# PromptShield Customer Guide

Welcome to PromptShield Pro. This guide covers setup and daily operation.

## System Requirements

- Python 3.8 or newer (Windows, macOS, or Linux).
- Any standard modern web browser (for the offline sandbox).
- No external packages required. Standard library only.

## Step 1: Unpack and Verify

1. Extract `PromptShield-Pro-v1.0.0.zip` to your chosen directory.
2. Open a terminal or PowerShell prompt in that directory.
3. Test execution:
   ```bash
   python -m promptshield.cli --help
   ```

## Step 2: Everyday Usage

### 1. Sanitising Piped Input
Pipe terminal logs directly into PromptShield:
```bash
cat error.log | python -m promptshield.cli redact > clean_prompt.txt
```

### 2. Sanitising with Rehydration
Save a session mapping so you can unmask the AI response later:
```bash
python -m promptshield.cli redact server.log --session bug42 --out safe.txt
```
Paste `safe.txt` into your AI assistant. When the assistant replies, copy its reply to `ai_reply.txt` and run:
```bash
python -m promptshield.cli restore ai_reply.txt --session bug42 --out final_code.py
```
All pseudonyms swap back to your real credentials locally.

### 3. Protecting Git Commits
Install the pre-commit hook into any git repository:
```bash
cd /path/to/your/git/repo
python -m promptshield.cli install-hook
```
Any staged commit with unmasked keys or credentials will be stopped.

### 4. Sanitising System Clipboard
Copy any text, then run:
```bash
python -m promptshield.cli clip
```
Your clipboard now holds the sanitised version.
