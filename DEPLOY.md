# Operational Deployment Guide

This guide gives the instructions to deploy PromptShield, configure payment collection, and withdraw money.

## 1. Capital Allocation

The permitted capital is $20 USD ($40 AUD).

### Option A: Zero Initial Cost (Recommended)

- Total initial spend: $0.00 USD.
- Hosting: Cloudflare Pages or GitHub Pages (free plan).
- Payment processor: Gumroad or Lemon Squeezy (charges a percentage fee only when a sale occurs).
- Remaining balance: $20.00 USD.

### Option B: Custom Domain Name

- Spend: $10.00 to $12.00 USD per year.
- Action: Register a domain name (for example, `promptshield.dev`) with Cloudflare Registrar.
- Remaining balance: $8.00 to $10.00 USD.

## 2. Published Product and Payout Setup

The product is published on Gumroad.

- **Product Page:** [https://lorthris.gumroad.com/l/promptshield-pro](https://lorthris.gumroad.com/l/promptshield-pro)
- **Product Identifier:** `zaXXDkTlDF8tfc0hiS9WZg==`
- **Price:** $19 USD
- **Launch Discount Code:** `LAUNCH20` (20 percent discount)

### Bank Setup on Gumroad

To receive your money:

1. Open your Gumroad dashboard and go to **Settings** -> **Payouts**.
2. Select **Australia** as your country.
3. Enter your Australian Bank State Branch (BSB) number and Account number.
4. Complete the identity verification form required by Australian financial regulations.

## 3. Deploy the Web Showcase (Zero Cost)

Deploy the files in `docs/` (or `web/`) to make the interactive sandbox public.

### Method 1: Cloudflare Pages

1. Log in to your Cloudflare dashboard.
2. Select **Compute (Workers & Pages)** -> **Create Application** -> **Pages**.
3. Drag and drop the `docs/` directory into the browser.
4. Your site will be live immediately on a free `*.pages.dev` address.

### Method 2: GitHub Pages

1. Create a public repository on GitHub (using `gh repo create promptshield --public`).
2. Push this repository to GitHub.
3. In repository settings, set **Pages** to deploy from the `main` branch under the `/web` folder.

## 4. When to Collect Money

- **Gumroad Schedule:** Payouts occur automatically every Friday for balances above $10 USD.
- **Deposit Method:** Direct electronic funds transfer into your Australian bank account.
- **Taxes:** The Merchant of Record automatically collects and remits goods and services tax (GST) and international value-added tax (VAT).

## 5. Traffic and Distribution

To generate sales without advertising expenses:

1. Post a **Show HN** on Hacker News: "Show HN: PromptShield - Offline secret scrubber for AI prompts".
2. Post on relevant technical forums: Reddit `r/programming`, `r/LocalLLaMA`, and `r/ClaudeAI`.
3. Open-source the base engine on GitHub and offer the Pro features, git hooks, and rehydration tools in the commercial bundle.
