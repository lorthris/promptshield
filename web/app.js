/**
 * PromptShield - Client-side interactive sanitiser
 * Zero telemetry - all calculations run directly in the browser memory.
 */

(function () {
  const rawInput = document.getElementById("raw-input");
  const cleanOutput = document.getElementById("clean-output");
  const inputStats = document.getElementById("input-stats");
  const btnSanitise = document.getElementById("btn-sanitise");
  const btnLoadSample = document.getElementById("btn-load-sample");
  const btnCopy = document.getElementById("btn-copy");
  const findingsSummary = document.getElementById("findings-summary");
  const findingsCount = document.getElementById("findings-count");
  const findingsList = document.getElementById("findings-list");

  // Detection rules matching PromptShield engine
  const RULES = [
    {
      name: "ANTHROPIC_KEY",
      regex: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,100}\b/g,
    },
    {
      name: "OPENAI_KEY",
      regex: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,100}\b/g,
    },
    {
      name: "GEMINI_KEY",
      regex: /\bAIzaSy[A-Za-z0-9_-]{33}\b/g,
    },
    {
      name: "AWS_KEY",
      regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g,
    },
    {
      name: "GITHUB_TOKEN",
      regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    },
    {
      name: "STRIPE_KEY",
      regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b/g,
    },
    {
      name: "DATABASE_URI",
      regex: /\b(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^\s:]+:[^\s@]+@[^\s/:]+(?::\d+)?\/[^\s]*\b/g,
    },
    {
      name: "EMAIL",
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    },
    {
      name: "AU_MOBILE",
      regex: /\b(?:\+?61\s?4|04)\d{2}[\s.-]?\d{3}[\s.-]?\d{3}\b/g,
    },
    {
      name: "PRIVATE_IP",
      regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    }
  ];

  function luhnCheck(numStr) {
    const digits = numStr.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits.charAt(i), 10);
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  function tfnCheck(numStr) {
    const digits = numStr.replace(/\D/g, "").split("").map(Number);
    if (digits.length === 8) {
      const weights = [10, 7, 8, 4, 6, 3, 5, 1];
      const sum = digits.reduce((acc, d, i) => acc + d * weights[i], 0);
      return sum % 11 === 0;
    }
    if (digits.length === 9) {
      const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
      const sum = digits.reduce((acc, d, i) => acc + d * weights[i], 0);
      return sum % 11 === 0;
    }
    return false;
  }

  function sanitiseText(text) {
    if (!text) return { sanitised: "", findings: [] };

    let findings = [];
    let valueToPseudonym = new Map();
    let categoryCounters = new Map();

    // Scan regex rules
    for (const rule of RULES) {
      const matches = [...text.matchAll(rule.regex)];
      for (const m of matches) {
        findings.push({
          rule: rule.name,
          value: m[0],
          index: m.index,
          length: m[0].length
        });
      }
    }

    // Check credit cards
    const ccRegex = /\b(?:\d[ -]?){13,19}\b/g;
    for (const m of text.matchAll(ccRegex)) {
      if (luhnCheck(m[0])) {
        findings.push({
          rule: "CREDIT_CARD",
          value: m[0],
          index: m.index,
          length: m[0].length
        });
      }
    }

    // Check Australian TFN
    const tfnRegex = /\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b/g;
    for (const m of text.matchAll(tfnRegex)) {
      if (tfnCheck(m[0])) {
        findings.push({
          rule: "AU_TFN",
          value: m[0],
          index: m.index,
          length: m[0].length
        });
      }
    }

    // Sort findings by position
    findings.sort((a, b) => a.index - b.index);

    // Filter overlapping findings
    const nonOverlapping = [];
    let lastEnd = -1;
    for (const f of findings) {
      const end = f.index + f.length;
      if (f.index >= lastEnd) {
        nonOverlapping.push(f);
        lastEnd = end;
      }
    }

    // Assign consistent pseudonyms
    for (const f of nonOverlapping) {
      if (!valueToPseudonym.has(f.value)) {
        const count = (categoryCounters.get(f.rule) || 0) + 1;
        categoryCounters.set(f.rule, count);
        valueToPseudonym.set(f.value, `[${f.rule}_${count}]`);
      }
    }

    // Build replacement
    let result = "";
    let cursor = 0;
    for (const f of nonOverlapping) {
      result += text.slice(cursor, f.index);
      result += valueToPseudonym.get(f.value);
      cursor = f.index + f.length;
    }
    result += text.slice(cursor);

    return {
      sanitised: result,
      findings: nonOverlapping
    };
  }

  // Event handlers
  rawInput.addEventListener("input", function () {
    inputStats.textContent = `${rawInput.value.length} chars`;
  });

  btnSanitise.addEventListener("click", function () {
    const raw = rawInput.value;
    const { sanitised, findings } = sanitiseText(raw);
    cleanOutput.value = sanitised;

    if (findings.length > 0) {
      findingsSummary.classList.remove("hidden");
      findingsCount.textContent = `${findings.length} Detection${findings.length === 1 ? "" : "s"}`;
      findingsList.innerHTML = findings
        .map(
          (f) =>
            `<div class="finding-chip">${f.rule}: <span>${f.value.slice(0, 6)}...</span></div>`
        )
        .join("");
    } else {
      findingsSummary.classList.add("hidden");
    }
  });

  btnLoadSample.addEventListener("click", function () {
    const sample = `[2026-09-21 14:02:11 ERROR] app.workers.syncer: Database connection timed out.
Connection String: postgres://prod_admin:p@ssw0rd9981!@db-internal.company.cloud:5432/finance_db
Caller: James Wilson (james.wilson@acme-systems.internal, mobile +61 412 345 678)
Worker Host: 10.240.12.89 (cluster: ap-southeast-2)
Failed API payload sync to external vendor:
{
  "anthropic_api_key": "sk-ant-api03-abcdef1234567890123456789012345678901234",
  "openai_fallback": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx",
  "aws_s3_key": "AKIAIOSFODNN7EXAMPLE",
  "stripe_customer_sync": "sk_test_51ABC123DEF456GHI789JKL012MNO345PQR678"
}
Please help debug why this database pool failed!`;

    rawInput.value = sample;
    inputStats.textContent = `${sample.length} chars`;
    btnSanitise.click();
  });

  btnCopy.addEventListener("click", function () {
    if (!cleanOutput.value) return;
    navigator.clipboard.writeText(cleanOutput.value).then(() => {
      const originalText = btnCopy.textContent;
      btnCopy.textContent = "Copied!";
      btnCopy.style.borderColor = "var(--accent-emerald)";
      btnCopy.style.color = "var(--accent-emerald)";
      setTimeout(() => {
        btnCopy.textContent = originalText;
        btnCopy.style.borderColor = "";
        btnCopy.style.color = "";
      }, 1800);
    });
  });
})();
