# PromptShield agent rules

Instructions for autonomous AI agents in this repository.

## Component map

- `promptshield/detector.py`: Heuristics, signatures, Shannon entropy, and checksums for secret and PII detection.
- `promptshield/redactor.py`: Deterministic pseudonym substitution and restore mapping.
- `promptshield/guard.py`: Heuristic firewall against prompt injections and jailbreaks.
- `promptshield/clipboard.py`: Local clipboard sanitiser with fallback mechanisms.
- `promptshield/cli.py`: Unified command-line interface and entry points.
- `docs/`: Static web demonstration and documentation served through GitHub Pages.
- `tests/`: Automated unit tests.

## Verification gate

Run all verification commands before you complete any change:

```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest tests/
python -m promptshield.cli scan promptshield/
```

## Security and secrets

- Keep secrets in the self-hosted Vaultwarden collection `promptshield`.
- Access and inject credentials with `python -B ~/.claude/tools/vw-run/vw_run.py --account promptshield`.
- Follow `C:/Users/James/.codex/skills/vault-secrets/SKILL.md` for secret storage, rotation, and injection.
- Never write credentials, tokens, or private keys to source files, tests, command parameters, or logs.

## Invariants

- Zero telemetry: All heuristics, pattern scans, and masking operations run locally. Do not add network calls or remote telemetry to core modules.
- Language: Use Australian English spelling in code identifiers, docstrings, comments, and documentation.
