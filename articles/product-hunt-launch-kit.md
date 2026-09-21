# Product Hunt Launch Kit: PromptShield

Ready-to-use launch submission for Product Hunt.

---

## 1. Product Details
- **Name:** PromptShield
- **Tagline:** Zero-telemetry secret sanitiser & prompt injection firewall for AI
- **Primary Category:** Developer Tools, Artificial Intelligence, Cybersecurity
- **Pricing:** Free Web Sandbox & Open Core / $19 Commercial Licences
- **Links:**
  - Website: https://lorthris.github.io/promptshield/
  - GitHub: https://github.com/lorthris/promptshield
  - Gumroad Store: https://lorthris.gumroad.com

---

## 2. Maker First Comment (Post Immediately Upon Launch)

```text
Hey Product Hunt community! 👋

I'm James, creator of PromptShield.

As developers, we're all using LLMs every day. But two major risks keep causing security headaches:
1. Accidentally pasting database URLs, API tokens, and customer PII into ChatGPT/Claude while debugging.
2. Attackers attempting prompt injections and jailbreaks on customer-facing AI agents.

We built PromptShield to solve both with zero external dependencies and 100% offline execution:

🛡️ Outbound: PromptShield Pro
- Replaces secrets with deterministic pseudonyms (e.g. [ANTHROPIC_KEY_1]) so LLM code reasoning stays intact.
- Two-way session rehydration: swap live variables back into AI replies with one command.
- Automated Git pre-commit hooks and system clipboard sanitiser daemon.

⚡ Inbound: PromptShield Guard
- Evaluates prompts in < 0.2ms (pure standard library Python).
- Catches direct prompt overrides, DAN/jailbreak personas, system prompt extraction leaks, and hidden unicode steganography.

Try the interactive browser playground with zero installation:
👉 https://lorthris.github.io/promptshield/

Everything runs in your local browser memory. No data ever touches our servers.

Would love to hear your feedback, feature ideas, or edge cases!
```
