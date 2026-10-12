# PromptShield coding agent rules

Guidelines for AI coding assistants working in this repository.

## Architecture boundaries

- `promptshield/detector.py`: Scans text for credentials, tokens, PII, and high-entropy secrets.
- `promptshield/redactor.py`: Applies deterministic masking and rehydration mappings.
- `promptshield/guard.py`: Detects and blocks prompt injections, jailbreaks, and system prompt leaks.
- `promptshield/clipboard.py`: Background system clipboard sanitiser.
- `promptshield/cli.py`: Unified command-line interface.
- `docs/`: Live interactive web application (GitHub Pages).
- `tests/`: Automated unit test suite.

## Verification commands

- Check lint: `python -m ruff check .`
- Check formatting: `python -m ruff format --check .`
- Run test suite: `python -m pytest tests/`
- Scan for secrets: `python -m promptshield.cli scan promptshield/`

## Secrets and Vaultwarden

- Store and inject secrets using Vaultwarden: `python -B ~/.claude/tools/vw-run/vw_run.py --account promptshield`.
- Follow `C:/Users/James/.codex/skills/vault-secrets/SKILL.md`.
- Never store or commit plain-text credentials.

## Conventions

- Local-only execution: Zero network calls or external telemetry in core modules.
- Australian English spelling in all documentation, comments, and messages.
