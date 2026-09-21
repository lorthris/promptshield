# PromptShield Commercial Launch Kit

Ready-to-use launch submissions designed to drive immediate organic traffic to your GitHub repository, live web sandbox, and Gumroad store.

---

## 1. Hacker News ("Show HN")

**Submit URL:** [news.ycombinator.com/submit](https://news.ycombinator.com/submit)  
**Title:** `Show HN: PromptShield – Zero-telemetry secret and prompt injection defense for AI`  
**URL:** `https://github.com/lorthris/promptshield` (or leave URL blank and use Text to tell the story)

### Text Post Version (Recommended for Show HN):

```
Show HN: PromptShield – Zero-telemetry secret sanitiser and prompt injection defense

Hi HN,

We built PromptShield (https://github.com/lorthris/promptshield), a local-first security tool for developers building with LLMs or sending code and logs into Claude, ChatGPT, and Gemini.

Two problems kept biting teams we spoke with:
1. Developers accidentally pasting database URLs, OpenAI/AWS tokens, and customer PII into web chats or terminal CLI tools.
2. Prompt injection and jailbreaks bypassing basic rules in customer-facing LLM agents.

PromptShield solves both with zero external packages (pure standard library Python) and zero telemetry:
- Outbound (PromptShield Pro): Masks credentials using deterministic pseudonyms (e.g. [ANTHROPIC_KEY_1]) so LLM reasoning remains intact. Supports two-way rehydration to swap real variables back into AI replies, an automated Git pre-commit hook, and a clipboard daemon. Includes ATO TFN Mod 11, Medicare, and Luhn checks.
- Inbound (PromptShield Guard): An ultra-fast (<0.2ms) pattern and heuristic firewall that blocks direct overrides, DAN/jailbreak personas, system prompt extraction leaks, and invisible unicode payloads before queries hit model APIs.

You can test both live in your browser (all client-side WebAssembly/JS, nothing sent over the wire):
https://lorthris.github.io/promptshield/

Code is open on GitHub: https://github.com/lorthris/promptshield
Commercial standalone packages and team licences: https://lorthris.gumroad.com

Feedback on detection heuristics and evasion edge cases is very welcome!
```

---

## 2. Reddit Posts

### A. r/Python
**Title:** `I built PromptShield: a zero-dependency, local secret & prompt injection defense suite for LLM workflows`  
**Body:**
```
Hey everyone,

I wanted to share PromptShield, a lightweight, zero-telemetry Python security suite for developers using AI models (Claude, OpenAI, Gemini).

It addresses two major risks:
1. Outbound leaks: Redacts API keys, private keys, database connection strings, and PII with consistent pseudonyms before sending prompts, with a reverse-rehydration command to restore live variables in AI responses.
2. Inbound attacks: A sub-millisecond (< 0.2ms) firewall that catches prompt injections, DAN/jailbreak personas, system prompt extraction attempts, and hidden zero-width unicode attacks.

Zero external dependencies (pure Python standard library).

- GitHub: https://github.com/lorthris/promptshield
- Interactive Web Demo: https://lorthris.github.io/promptshield/
- Gumroad Store: https://lorthris.gumroad.com

Would love feedback on our regex suites and edge case coverage!
```

### B. r/LocalLLaMA / r/cybersecurity
**Title:** `Tool: Local prompt sanitiser & injection firewall (0.2ms latency, zero telemetry)`  
**Body:**
```
If you run LLM pipelines or terminal AI tools, credential leaks and prompt injection are persistent headaches.

I open-sourced PromptShield:
- Detects 50+ API key signatures (OpenAI, Anthropic, AWS, Stripe, etc.) + Shannon entropy.
- Intercepts ChatML/LLaMA delimiter injection, markdown image data exfiltration, and DAN jailbreak patterns.
- Runs 100% locally with zero external network calls.

Try the interactive browser playground: https://lorthris.github.io/promptshield/
Source: https://github.com/lorthris/promptshield
```

---

## 3. X / Twitter Launch Thread

**Post 1:**
> Stop leaking database passwords and API keys into ChatGPT and Claude prompts.
> 
> Introducing PromptShield: a local, zero-telemetry security suite that sanitises credentials with deterministic pseudonyms AND blocks prompt injections in < 0.2ms.
> 
> 🛡️ 100% offline. Zero tracking.
> 
> Try live: https://lorthris.github.io/promptshield/ 🧵👇

**Post 2:**
> 1/ Outbound Protection (PromptShield Pro):
> It replaces keys with consistent tokens like `[ANTHROPIC_KEY_1]` so the model keeps its code reasoning context.
> 
> Then run `promptshield restore` on the reply to automatically swap back your real local variables.

**Post 3:**
> 2/ Inbound Defense (PromptShield Guard):
> A sub-millisecond firewall that intercepts:
> - DAN & persona jailbreaks
> - System prompt extraction attacks
> - Markdown image tracking pixels
> - Hidden zero-width unicode exploits

**Post 4:**
> Full source code, CLI installer, and automated Git pre-commit hooks are available now:
> 
> 📦 GitHub: https://github.com/lorthris/promptshield
> 🛒 Gumroad Store: https://lorthris.gumroad.com
