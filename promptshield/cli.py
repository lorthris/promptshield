"""Command-line interface for PromptShield."""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import List, Optional

from promptshield.detector import Detector
from promptshield.guard import PromptGuard
from promptshield.redactor import Redactor


def get_stdin_or_file_content(path_arg: Optional[str]) -> str:
    """Read content from named file or standard input."""
    if path_arg and path_arg != "-":
        target = Path(path_arg)
        if not target.exists():
            sys.stderr.write(f"Error: File not found: {path_arg}\n")
            sys.exit(2)
        return target.read_text(encoding="utf-8", errors="replace")
    if sys.stdin.isatty():
        sys.stderr.write("PromptShield: Reading from standard input (Ctrl+Z and Enter to complete)...\n")
    return sys.stdin.read()


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan input and report detected sensitive findings."""
    detector = Detector(check_entropy=not args.no_entropy)
    content = get_stdin_or_file_content(args.file)
    findings = detector.scan(content)

    if args.json:
        result = [
            {
                "category": f.category,
                "rule_name": f.rule_name,
                "value_masked": f.value[:4] + "..." + f.value[-4:] if len(f.value) > 8 else "***",
                "start": f.start,
                "end": f.end,
                "confidence": f.confidence,
            }
            for f in findings
        ]
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        if not findings:
            sys.stdout.write("Clean: No sensitive credentials or PII detected.\n")
            return 0

        sys.stdout.write(f"Found {len(findings)} sensitive item(s):\n\n")
        sys.stdout.write(f"{'Category':<12} {'Rule':<24} {'Confidence':<12} {'Offset':<12} {'Sample'}\n")
        sys.stdout.write("-" * 75 + "\n")
        for f in findings:
            preview = f.value[:6] + "..." + f.value[-4:] if len(f.value) > 12 else f.value
            sys.stdout.write(f"{f.category:<12} {f.rule_name:<24} {f.confidence:<12.2f} {f.start:<12} {preview}\n")
        sys.stdout.write("\n")

    return 1 if findings else 0


def cmd_redact(args: argparse.Namespace) -> int:
    """Mask sensitive tokens and write sanitised text."""
    detector = Detector(check_entropy=not args.no_entropy)
    redactor = Redactor(detector=detector, style=args.style)
    content = get_stdin_or_file_content(args.file)

    result = redactor.redact(content, session_id=args.session)

    if args.in_place and args.file and args.file != "-":
        Path(args.file).write_text(result.sanitised_text, encoding="utf-8")
        sys.stderr.write(f"Updated {args.file} in place ({len(result.findings)} items masked).\n")
    elif args.out:
        Path(args.out).write_text(result.sanitised_text, encoding="utf-8")
        sys.stderr.write(f"Wrote sanitised output to {args.out} ({len(result.findings)} items masked).\n")
    else:
        sys.stdout.write(result.sanitised_text)

    if args.session:
        sys.stderr.write(f"\n[Session saved: {args.session} ({len(result.mapping)} tokens mapped for restore)]\n")

    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore pseudonyms back to real tokens using a session."""
    redactor = Redactor()
    content = get_stdin_or_file_content(args.file)

    if not args.session and not args.mapping:
        sys.stderr.write("Error: Either --session <id> or --mapping <file> is required to restore tokens.\n")
        return 2

    mapping_dict = None
    if args.mapping:
        map_path = Path(args.mapping)
        if not map_path.exists():
            sys.stderr.write(f"Error: Mapping file not found: {args.mapping}\n")
            return 2
        with open(map_path, "r", encoding="utf-8") as f:
            mapping_dict = json.load(f)

    restored = redactor.restore(content, session_id=args.session, mapping=mapping_dict)

    if args.out:
        Path(args.out).write_text(restored, encoding="utf-8")
        sys.stderr.write(f"Wrote restored text to {args.out}\n")
    else:
        sys.stdout.write(restored)

    return 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    """Install a pre-commit git hook to block un-sanitised secrets."""
    git_dir = Path.cwd() / ".git"
    if not git_dir.exists():
        sys.stderr.write("Error: Current directory is not a git repository.\n")
        return 1

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    pre_commit = hooks_dir / "pre-commit"

    script = """#!/bin/sh
# PromptShield automated pre-commit secret leak protection
echo "[PromptShield] Scanning staged files for secrets and PII..."

# Scan git diff of staged changes
DIFF=$(git diff --cached)
if [ -z "$DIFF" ]; then
    exit 0
fi

# Pipe diff into PromptShield scan
echo "$DIFF" | python -m promptshield.cli scan
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo ""
    echo "[PromptShield] COMMIT BLOCKED: Sensitive credentials or PII detected in staged changes!"
    echo "To sanitise before committing, run: python -m promptshield.cli redact <file>"
    echo "Or override with: git commit --no-verify"
    exit 1
fi

exit 0
"""
    pre_commit.write_text(script, encoding="utf-8")
    sys.stdout.write(f"Successfully installed PromptShield pre-commit hook to {pre_commit}\n")
    return 0


def cmd_guard(args: argparse.Namespace) -> int:
    """Analyze prompt for injection attacks, jailbreaks, and leaks."""
    guard = PromptGuard(threshold=args.threshold)
    content = get_stdin_or_file_content(args.file)
    result = guard.scan(content)

    if args.json:
        sys.stdout.write(json.dumps(result.to_dict(), indent=2) + "\n")
    else:
        if result.is_safe:
            sys.stdout.write(f"Clean: Prompt passed guard inspection (Threat Score: {result.threat_score}/100, Level: {result.threat_level.value.upper()})\n")
        else:
            sys.stdout.write(f"Threat Detected: Level {result.threat_level.value.upper()} (Score: {result.threat_score}/100, Threshold: {args.threshold})\n\n")
            sys.stdout.write(f"{'Category':<22} {'Score':<8} {'Offset':<12} {'Description'}\n")
            sys.stdout.write("-" * 75 + "\n")
            for f in result.findings:
                sys.stdout.write(f"{f.category.value:<22} {f.score:<8} {f.start:<12} {f.description}\n")
            sys.stdout.write("\n")

        if args.sanitize:
            if args.out:
                Path(args.out).write_text(result.sanitized_prompt, encoding="utf-8")
                sys.stdout.write(f"Wrote sanitised prompt to {args.out}\n")
            else:
                sys.stdout.write("--- Sanitised Prompt ---\n")
                sys.stdout.write(result.sanitized_prompt + "\n")

    return 0 if result.is_safe else 1



def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="Local zero-telemetry secret and PII sanitiser for developer AI workflows.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan text or file for secrets and PII")
    p_scan.add_argument("file", nargs="?", default=None, help="File to scan (or standard input)")
    p_scan.add_argument("--json", action="store_true", help="Output findings as structured JSON")
    p_scan.add_argument("--no-entropy", action="store_true", help="Disable Shannon entropy heuristic")

    # redact
    p_redact = subparsers.add_parser("redact", help="Sanitise text by masking sensitive values")
    p_redact.add_argument("file", nargs="?", default=None, help="File to redact (or standard input)")
    p_redact.add_argument("--style", choices=["pseudonym", "redacted", "hash"], default="pseudonym", help="Masking style")
    p_redact.add_argument("--session", type=str, default=None, help="Session identifier for reverse rehydration")
    p_redact.add_argument("--out", type=str, default=None, help="Write sanitised output to destination path")
    p_redact.add_argument("--in-place", action="store_true", help="Modify input file in place")
    p_redact.add_argument("--no-entropy", action="store_true", help="Disable Shannon entropy heuristic")

    # restore
    p_restore = subparsers.add_parser("restore", help="Rehydrate pseudonyms in AI responses back to real secrets")
    p_restore.add_argument("file", nargs="?", default=None, help="File to restore (or standard input)")
    p_restore.add_argument("--session", type=str, default=None, help="Session identifier to restore from")
    p_restore.add_argument("--mapping", type=str, default=None, help="Path to JSON mapping file")
    p_restore.add_argument("--out", type=str, default=None, help="Write restored output to destination path")

    # install-hook
    subparsers.add_parser("install-hook", help="Install git pre-commit hook in current repository")

    # clip
    p_clip = subparsers.add_parser("clip", help="Sanitise text currently on clipboard")
    p_clip.add_argument("--session", type=str, default=None, help="Session identifier for reverse rehydration")

    # guard
    p_guard = subparsers.add_parser("guard", help="Scan prompt for injections, jailbreaks, and leaks")
    p_guard.add_argument("file", nargs="?", default=None, help="File to analyze (or standard input)")
    p_guard.add_argument("--threshold", type=int, default=40, help="Threat score threshold (default: 40)")
    p_guard.add_argument("--json", action="store_true", help="Output evaluation as JSON")
    p_guard.add_argument("--sanitize", action="store_true", help="Neutralize threats and output sanitized text")
    p_guard.add_argument("--out", type=str, default=None, help="Write sanitized output to file")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "redact":
        return cmd_redact(args)
    elif args.command == "restore":
        return cmd_restore(args)
    elif args.command == "install-hook":
        return cmd_install_hook(args)
    elif args.command == "clip":
        from promptshield.clipboard import sanitise_clipboard
        sanitise_clipboard(session_id=args.session)
        return 0
    elif args.command == "guard":
        return cmd_guard(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
