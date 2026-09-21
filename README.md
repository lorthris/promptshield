# PromptShield

Local cybersecurity and privacy tool suite for artificial intelligence workflows.

[![PyPI](https://img.shields.io/pypi/v/promptshield-core.svg)](https://pypi.org/project/promptshield-core/)
[![Tests](https://img.shields.io/badge/tests-32%20passing-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Licence](https://img.shields.io/badge/licence-Commercial%20%2F%20Open%20Core-cyan)](https://lorthris.gumroad.com/l/promptshield-suite)
[![Interactive Sandbox](https://img.shields.io/badge/demo-live%20sandbox-emerald)](https://lorthris.github.io/promptshield/)
[![Coupon](https://img.shields.io/badge/launch%20coupon-20%25%20off%20(LAUNCH20)-orange)](https://lorthris.gumroad.com/l/promptshield-suite)

## Purpose

Artificial intelligence models can record data that users transmit in prompts. This tool suite gives full-stack protection:
1. **PromptShield Pro:** Detects and masks credentials, passwords, database URIs, and identity numbers before data leaves your computer.
2. **PromptShield Guard:** Analyzes incoming user prompts in less than 0.2 milliseconds to block prompt injections, persona jailbreaks, and system prompt extraction.

All calculations run locally on your device with zero telemetry and zero network calls.

---

## Live Interactive Sandbox

Test both engines directly in your browser:  
👉 **[lorthris.github.io/promptshield](https://lorthris.github.io/promptshield/)**

---

## Architecture and Core Modules

```
PromptShield/
├── promptshield/
│   ├── detector.py      # 50+ secret signatures, Luhn CC, ATO TFN, Shannon entropy
│   ├── redactor.py      # Deterministic pseudonym substitution and restore mapping
│   ├── guard.py         # Prompt injection, jailbreak, and leak defense engine
│   ├── clipboard.py     # System clipboard background sanitiser
│   └── cli.py           # Unified command-line interface
├── docs/                # Live interactive web application (GitHub Pages)
└── tests/               # 32 automated unit tests
```

---

## Quick Install

Install directly from PyPI:
```bash
pip install promptshield-core
```
Or install the latest commit directly from GitHub:
```bash
pip install git+https://github.com/lorthris/promptshield.git
```
Or run directly from the cloned repository without installation:
```bash
python -m promptshield.cli --help
```

---

## Commands

### 1. Scan Files for Sensitive Credentials
```bash
python -m promptshield.cli scan path/to/file.txt
python -m promptshield.cli scan path/to/file.txt --json
```

### 2. Mask Secrets with Deterministic Pseudonyms
```bash
python -m promptshield.cli redact dirty.log --out clean.log --session incident42
```

### 3. Restore Live Secrets in Model Output
```bash
python -m promptshield.cli restore ai_reply.txt --session incident42 --out final.txt
```

### 4. Guard LLMs Against Prompt Injections and Jailbreaks
```bash
python -m promptshield.cli guard user_prompt.txt
python -m promptshield.cli guard user_prompt.txt --sanitize --out clean_prompt.txt
python -m promptshield.cli guard user_prompt.txt --json
```

### 5. Sanitise System Clipboard
```bash
python -m promptshield.cli clip
```

### 6. Install Automated Git Pre-Commit Hook
```bash
python -m promptshield.cli install-hook
```

### 7. GitHub Actions CI/CD Integration
```yaml
# .github/workflows/security.yml
- name: PromptShield Security Scanner
  uses: lorthris/promptshield@v1
```

---

## Commercial Licences

Commercial developer packages are available on Gumroad with perpetual rights and free updates.  
🎉 **Launch Special:** Use code **`LAUNCH20`** at checkout for **20% off** any tool or bundle.

| Package | Purpose | Price (USD) | Link |
| :--- | :--- | :--- | :--- |
| **PromptShield Pro** | Outbound secret & PII sanitiser, Git hook, clipboard daemon | \$19 | [Buy Pro Edition](https://lorthris.gumroad.com/l/promptshield-pro) |
| **PromptShield Guard** | Inbound prompt injection, jailbreak & leak firewall | \$19 | [Buy Guard Edition](https://lorthris.gumroad.com/l/promptshield-guard) |
| **Complete AI Security Suite** | Both full packages (Save \$9) | \$29 | [Buy Complete Suite](https://lorthris.gumroad.com/l/promptshield-suite) |

---

## Testing

Run the automated test suite:

```bash
python -B -m unittest discover -s tests -p "test_*.py"
```
