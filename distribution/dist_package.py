"""Automated build and packaging script for PromptShield commercial distribution."""

import os
from pathlib import Path
import shutil
import zipfile


def build_distribution():
    base_dir = Path(__file__).resolve().parent.parent
    dist_output = base_dir / "dist_output"
    staging_dir = dist_output / "PromptShield-Pro-v1.0.0"

    # Reset staging
    if dist_output.exists():
        shutil.rmtree(dist_output)
    staging_dir.mkdir(parents=True, exist_ok=True)

    print(f"[PromptShield] Building commercial release package in {staging_dir}...")

    # Copy core Python package
    shutil.copytree(
        base_dir / "promptshield",
        staging_dir / "promptshield",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    # Copy web sandbox asset
    shutil.copytree(base_dir / "web", staging_dir / "web")

    # Copy root documentation
    for doc in ["README.md", "DEPLOY.md"]:
        if (base_dir / doc).exists():
            shutil.copy(base_dir / doc, staging_dir / doc)

    # Create quickstart guide in package
    quickstart_content = """# PromptShield Pro - Quickstart Guide

Thank you for purchasing PromptShield Pro.

## 1. Quick Installation

### Windows PowerShell (PowerShell 5.1 or 7):
```powershell
python -m pip install -e .
```
Or run directly without installation:
```powershell
python -m promptshield.cli --help
```

### Linux / macOS:
```bash
python3 -m pip install -e .
```

## 2. Typical Workflows

### A. Sanitise a log file before pasting into Claude or ChatGPT:
```bash
python -m promptshield.cli redact incident.log --session incident_01 > clean.log
```

### B. Restore masked tokens in the AI response:
```bash
python -m promptshield.cli restore ai_response.txt --session incident_01 > restored_solution.txt
```

### C. Sanitise your system clipboard instantly:
```bash
python -m promptshield.cli clip
```

### D. Install Git Pre-Commit Hook to protect your repository:
```bash
python -m promptshield.cli install-hook
```

### E. Offline Browser Sandbox:
Open `web/index.html` in any modern web browser. No internet connection or server required.
"""
    (staging_dir / "QUICKSTART.md").write_text(quickstart_content, encoding="utf-8")

    # Create setup.py for pip install
    setup_content = """from setuptools import setup, find_packages

setup(
    name="promptshield",
    version="1.0.0",
    description="Local zero-telemetry secret and PII sanitiser for developer AI workflows",
    author="PromptShield",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "promptshield = promptshield.cli:main",
        ],
    },
    python_requires=">=3.8",
)
"""
    (staging_dir / "setup.py").write_text(setup_content, encoding="utf-8")

    # Create ZIP archive
    zip_path = dist_output / "PromptShield-Pro-v1.0.0.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(staging_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(staging_dir.parent)
                zipf.write(file_path, arcname)

    size_kb = zip_path.stat().st_size / 1024
    print(f"[PromptShield] Package created: {zip_path} ({size_kb:.1f} KB)")
    print("[PromptShield] Ready for upload to Gumroad / Lemon Squeezy.")
    return zip_path


if __name__ == "__main__":
    build_distribution()
