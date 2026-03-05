# SILA Entropy

![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![NIST 800-63B](https://img.shields.io/badge/NIST-800--63B-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen)

Password strength auditing tool with:
- breach checking (HIBP k-anonymity),
- entropy + pattern-aware analysis,
- optional zxcvbn guessability,
- scenario-based offline/online crack-time estimation.

This project is designed for password strength evaluation, not as a standalone authentication defense system.

## Features

- Strength tiers: `Very Weak`, `Weak`, `Moderate`, `Strong`
- Breach status via Have I Been Pwned (Pwned Passwords API)
- Multi-model estimation:
  - random brute-force model
  - pattern-aware model
  - guessability model (`zxcvbn` if available, fallback otherwise)
- Conservative estimate uses the fastest plausible crack path
- All-scenario mode tests all combinations of hash profile, attacker scale, and online defense profile
- Confidence bands: best / expected / worst

## Project Structure

```text
.
|- sila.py              # Facade + main entrypoint
|- sila_cli.py          # Terminal UI / workflow
|- sila_analysis.py     # Strength labels, verdict logic, explanation output
|- sila_models.py       # Entropy, timing, pattern and guess models
|- sila_breach.py       # HIBP + dictionary loading
|- sila_config.py       # Constants, profiles, wordlist loading
|- wordlists/
|  |- rockyou.txt.example
|  `- common_words.txt
`- test_sila.py         # Unit tests
```

## Requirements

- Python 3.9+
- Packages:
  - `requests`
  - `rich`
  - `zxcvbn` (optional but recommended)

Install:

```bash
pip install requests rich zxcvbn
```

If `zxcvbn` is not installed, the app automatically uses `pattern_fallback`.

## Usage

```bash
python sila.py
```

The app will:
1. Print active guessability engine (`zxcvbn` or `pattern_fallback`)
2. Test all configured scenario combinations
3. Ask for comma-separated target passwords
4. Show a concise results table
5. Show a detailed explanation panel for the first target

## Wordlists

`COMMON_PASSWORDS` loads from `wordlists/rockyou.txt`.

### rockyou Setup

1. Place your wordlist at:
   - `wordlists/rockyou.txt`
2. Keep it out of git:
   - `.gitignore` already excludes `wordlists/rockyou.txt`
3. Tune load size in `sila_config.py`:
   - `ROCKYOU_MAX_WORDS = 1_000_000`
   - use `max_words=None` in loader call for full-file load
4. If missing, SILA falls back to a built-in minimal password set.

`COMMON_WORDS` loads from:
- `wordlists/common_words.txt`

## Configuration

Edit `sila_config.py` for:
- `NIST_MIN_LENGTH`
- `HASH_PROFILES`
- `ATTACKER_SCALE`
- `ONLINE_DEFENSE`
- `ROCKYOU_MAX_WORDS`

## Testing

```bash
python -m unittest -v
```

## Notes and Limits

- This tool estimates password strength/risk; it cannot provide exact crack-time guarantees.
- Real-world security still depends on operational controls such as MFA, lockout/rate limiting, secure hashing parameters, and monitoring.
