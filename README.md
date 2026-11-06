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
* Localized Threat Model: a 10,000-term romanised Khmer/Cambodian wordlist (places, names, common words) feeds both the pattern model and zxcvbn, so regional passwords get realistic crack times. Optional Khmer-script dictionary support.
* NIST 2026 Ready: compliance checking against NIST SP 800-63B Rev. 4 (length floor, breach corpus, blocklist, context-specific words).
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
pip install -r requirements.txt
```

If `zxcvbn` is not installed, the app automatically uses `pattern_fallback`.

### Usage

```bash
python sila.py
```

If the passwords are only used as one factor of MFA, NIST's minimum length is 8 instead of 15:

```bash
python sila.py --mfa
```

The app will:
1. Print active guessability engine (`zxcvbn` or `pattern_fallback`) and wordlist sizes
2. Test all configured scenario combinations
3. Ask for comma-separated target passwords (input is hidden; write `\,` for a comma inside a password)
4. Show a concise results table
5. Show a detailed explanation panel for the first target

### Wordlists

All wordlists live in `wordlists/`:

| File | Used for |
| --- | --- |
| `common_passwords.txt` | small bundled blocklist (always loaded) |
| `rockyou.txt` | full common-password blocklist (optional, not in git) |
| `common_words.txt` | dictionary words for the pattern model and blocklist |
| `local_threat_terms.txt` | 10,000 romanised Khmer/Cambodian terms |
| `khmer_dict.txt` | optional extra local terms, Latin or Khmer script |

### rockyou Setup

1. Place your wordlist at:
   - `wordlists/rockyou.txt`
2. Keep it out of git:
   - `.gitignore` already excludes `wordlists/rockyou.txt`
3. Tune load size in `sila_config.py`:
   - `ROCKYOU_MAX_WORDS = 1_000_000` (rockyou is ordered by frequency, so this keeps the most common)
   - `ROCKYOU_MAX_WORDS = None` loads the full file (needs several GB of RAM).
4. If missing, SILA uses only the bundled `common_passwords.txt`; the startup line tells you which is active.

### NIST SP 800-63B Rev. 4 checks

A password is **Compliant** when all of these pass (section 3.1.1.2):

- **Length**: at least 15 characters (8 with `--mfa`), counted as Unicode code points after normalisation.
- **Breach corpus**: not found in Have I Been Pwned. If the lookup fails the result is **Unverified**, never Compliant.
- **Blocklist**: the password, or its base word once leetspeak and leading/trailing digits and symbols are removed, is not a common password, dictionary word or local term.
- **Context-specific words**: does not contain words from `CONTEXT_WORDS` in `sila_config.py` (set this to your system and organisation names).

NIST forbids composition rules (required uppercase, symbols, etc.), so none are applied. The **SAFE** verdict requires NIST compliance *and* a Strong rating under the fastest attack scenario.

### Configuration

Edit `sila_config.py` for:
- `NIST_MIN_LENGTH`
- `HASH_PROFILES`
- `ATTACKER_SCALE`
- `ONLINE_DEFENSE`
- `ROCKYOU_MAX_WORDS`
- `CONTEXT_WORDS`

### Testing

```bash
python -m unittest -v
```

## 📋 Notes and Limits

- This tool estimates password strength/risk; it cannot provide exact crack-time guarantees.
- The Strength tier uses the fastest scenario (unsalted SHA-1 on a 1,000-GPU cluster), so it is deliberately pessimistic.
- Khmer-script passphrases are only recognised as words if you supply them in `wordlists/khmer_dict.txt`; the bundled list is romanised.
- Real-world security still depends on operational controls such as MFA, lockout/rate limiting, secure hashing parameters, and monitoring.

## ⚠️ Disclaimer

This tool is designed for security evaluation and auditing purposes only. While SILA provides high-accuracy estimations, real-world security requires a defense-in-depth approach including MFA (FIDO2/Passkeys), rate-limiting, and continuous monitoring.
