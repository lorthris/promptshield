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

## Project navigation

Use `docs/project_map/INDEX.md` or open `docs/project_map/index.html` before broad searches.
The authored source is `docs/project_map/project_map_source.json`.

Run `python scripts/project_map.py q <path-or-words>` for ownership and related context.
Use `impact` and `tests` with the same target before a change. Use `brief` for the command card.
Ordinary code edits refresh the live index on the next query.
Update the authored source when components, ownership, workflows or boundaries change.
After an authored-source or included-path change, run
`python scripts/project_map.py build` and `python scripts/project_map.py check`.
The launcher uses the shared engine under `~/.claude/tools/project-map`;
set `PROJECT_MAP_ENGINE` to its `project_map.py` file for a separate installation.
Keep credentials, local state, caches and generated packages out of content queries. The manifest includes metadata for tracked and intended paths. Use the local workspace snapshot to inspect ignored and untracked path metadata.
