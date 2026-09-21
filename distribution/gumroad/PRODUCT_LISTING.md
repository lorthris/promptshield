# Gumroad Product Listing Details

Copy and paste these exact fields into your Gumroad or Lemon Squeezy product setup.

## Basic Information

- **Product Name:** PromptShield Pro - Local Secret & PII Sanitiser for AI
- **Subtitle:** Prevent API keys, passwords, and sensitive identity data from leaking into LLMs.
- **Price:** $19 USD (Lifetime access, free updates)
- **Category:** Developer Tools / Software
- **Format:** Digital Download (.zip)

## Product Description (Copy to Gumroad)

Pasting error logs, stack traces, and configuration files into ChatGPT, Claude, or Gemini risks exposing private keys, connection strings, and user PII.

PromptShield is a local, zero-telemetry tool suite designed for developers and engineering teams. It detects sensitive credentials and masks them with consistent pseudonyms before your data leaves your computer.

### Key Capabilities

1. **Deterministic Pseudonyms**
Identical secrets receive identical tokens throughout the prompt. The LLM retains full structural context and relational reasoning without seeing real credentials.

2. **Two-Way Session Rehydration**
Restore masked tokens in LLM output locally. Send redacted prompts to Claude or GPT, then run `promptshield restore` to swap back real values on your machine.

3. **50+ Secret Signatures & Shannon Entropy**
Catches OpenAI, Anthropic, Gemini, AWS, Stripe, Slack, and GitHub keys, database connection strings, RSA private keys, JWTs, and high-entropy generated strings.

4. **Australian & International Identity Rules**
Native validation for Australian Tax File Numbers (ATO Modulus 11), Medicare numbers, Australian mobiles, international credit cards (Luhn check), and private IP blocks.

5. **Git Pre-Commit Hook**
Blocks commits that contain un-sanitised secrets before they reach GitHub or GitLab.

6. **Clipboard Sanitiser**
Sanitise whatever is on your clipboard with one command before pasting into web browsers.

7. **Offline Web Sandbox**
Single-page application included for browser-based inspection with zero internet requirement.

### What You Receive

- Full Python CLI source code (zero external dependencies).
- Standalone offline web application.
- Automated pre-commit hook installer.
- Quickstart documentation and usage examples.
- Perpetual licence for personal and commercial development.
