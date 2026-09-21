# How to Stop Leaking Production Secrets into ChatGPT, Claude, and Gemini

*Tags: python, ai, security, devops, privacy*
*Canonical URL: https://lorthris.github.io/promptshield/prevent-api-key-leaks-ai.html*

Every engineering team building with LLMs faces the same terrifying incident: a developer encounters a cryptic 500 error, copies the terminal traceback, and pastes it directly into ChatGPT or Claude to ask for debugging assistance.

Inside that stack trace was an active PostgreSQL connection string with production credentials, an AWS secret access key, or a customer's personal details.

Once that prompt hits the network, those bytes reside in vendor session histories, telemetry pools, and inference logs.

In this guide, we examine why traditional regex find-and-replace fails, how deterministic pseudonyms preserve reasoning context, and how to automate local sanitisation with zero performance penalty.

---

## The Flaw with Naive Redaction

Most teams try writing a quick bash script or regex that replaces detected keys with `[REDACTED]`.

Here is the problem: **LLMs need relational structure to solve code bugs.**

Consider this error log:
```python
# Unmasked original:
primary_db = connect("postgres://admin:secretA@db1.internal/app")
replica_db = connect("postgres://readonly:secretB@db2.internal/app")
```

If both URIs are replaced with `[REDACTED]`, the LLM sees:
```python
primary_db = connect("[REDACTED]")
replica_db = connect("[REDACTED]")
```

The model can no longer tell if the failure is caused by passing the read-only credentials to the primary database, or if the connection hostnames differ.

### The Solution: Deterministic Pseudonymisation

Instead of erasing tokens, replace them deterministically:
```python
primary_db = connect("[DATABASE_URI_1]")
replica_db = connect("[DATABASE_URI_2]")
```

Every occurrence of `secretA` becomes `[DATABASE_URI_1]`, while `secretB` consistently becomes `[DATABASE_URI_2]`. The AI retains 100% of the relational context, correctly identifies the logic flaw, and never sees your real credentials.

---

## Two-Way Reverse Rehydration

The second challenge is applying the AI's fix. If Claude responds with:
```python
# Fix: update the connection pool settings for [DATABASE_URI_1]
pool = create_pool("[DATABASE_URI_1]", max_connections=20)
```

You normally have to manually paste back your real passwords.

With a local two-way session mapping, you simply run:
```bash
python -m promptshield.cli restore claude_response.py --session incident42
```
The tool swaps back your local variables automatically.

---

## Automating Defense at the Developer Boundary

The easiest way to prevent accidents is stopping them before data leaves your workstation:

1. **Automated Git Pre-Commit Hooks:** Intercept secrets before they reach GitHub or GitLab.
2. **Clipboard Daemon:** Automatically scrub credentials from your system clipboard before you paste into your web browser.

You can test this interactive sanitisation live directly in your browser without installing anything:
👉 **[Try the PromptShield Interactive Sandbox](https://lorthris.github.io/promptshield/)**

For full source code and automated CLI installers, check out the [PromptShield GitHub Repository](https://github.com/lorthris/promptshield).
