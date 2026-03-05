# SILA Entropy

![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![NIST 2026 Compliant](https://img.shields.io/badge/NIST-800--63B--4-green.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

<img width="879" height="314" alt="image" src="https://github.com/user-attachments/assets/87429d50-33d5-4d44-8dd8-debf48f12a62" />

SILA Entropy is a high-fidelity password auditing suite designed for the Ministry of Interior. It utilizes multi-model estimation, Khmer linguistic threat analysis, and k-anonymity breach detection to provide a 2026-standard security verdict.

---
## 🛰️ Core Capabilities
* Breach Intelligence: Real-time $k$-anonymity interrogation via the Have I Been Pwned API.
* Multi-Model Estimation: * Brute-Force: Mathematical entropy vs. State-level GPU clusters ($10^{11}$ guesses/sec).
* Pattern-Aware: Detection of "human habits" (trailing digits, leetspeak).
* Guessability: Deep analysis via zxcvbn with pattern_fallback.
* Localized Threat Model: Specialized Khmer dictionary integration to detect regional password patterns.
* NIST 2026 Ready: Built-in compliance checking for the 15-character security floor.
* Confidence Bands: Best, Expected, and Worst-case "Time-to-Entry" (ETE) scenarios.


## 🧪 Features

- Strength tiers: `Very Weak`, `Weak`, `Moderate`, `Strong`
- Breach status via Have I Been Pwned (Pwned Passwords API)
- Multi-model estimation:
  - random brute-force model
  - pattern-aware model
  - guessability model (`zxcvbn` if available, fallback otherwise)
- Conservative estimate uses the fastest plausible crack path
- All-scenario mode tests all combinations of hash profile, attacker scale, and online defense profile
- Confidence bands: best / expected / worst

---
## 🚀 Getting Started
### Requirements

- Python 3.9+
- Packages:
  - `requests`
  - `rich`
  - `zxcvbn` (optional but recommended)

### Install:

```bash
pip install requests rich zxcvbn
```

If `zxcvbn` is not installed, the app automatically uses `pattern_fallback`.

### Usage

```bash
python sila.py
```

The app will:
1. Print active guessability engine (`zxcvbn` or `pattern_fallback`)
2. Test all configured scenario combinations
3. Ask for comma-separated target passwords
4. Show a concise results table
5. Show a detailed explanation panel for the first target

### Wordlists

`COMMON_PASSWORDS` now loads from `wordlists/rockyou.txt`.

### rockyou Setup

1. Place your wordlist at:
   - `wordlists/rockyou.txt`
2. Keep it out of git:
   - `.gitignore` already excludes `wordlists/rockyou.txt`
3. Tune load size in `sila_config.py`:
   - `ROCKYOU_MAX_WORDS = 1_000_000`
   - `max_words = None` (full file load).
4. If missing, SILA falls back to a built-in minimal password set.

`COMMON_WORDS` loads from:
- `wordlists/common_words.txt`

### Configuration

Edit `sila_config.py` for:
- `NIST_MIN_LENGTH`
- `HASH_PROFILES`
- `ATTACKER_SCALE`
- `ONLINE_DEFENSE`
- `ROCKYOU_MAX_WORDS`

### Testing

```bash
python -m unittest -v
```

## 📋 Notes and Limits

- This tool estimates password strength/risk; it cannot provide exact crack-time guarantees.
- Real-world security still depends on operational controls such as MFA, lockout/rate limiting, secure hashing parameters, and monitoring.

## ⚠️ Disclaimer

This tool is designed for security evaluation and auditing purposes only. While SILA provides high-accuracy estimations, real-world security requires a defense-in-depth approach including MFA (FIDO2/Passkeys), rate-limiting, and continuous monitoring.
