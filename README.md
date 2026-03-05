# SILA Entropy

Password strength auditing tool with:
- breach checking (HIBP k-anonymity),
- entropy + pattern-aware analysis,
- optional zxcvbn guessability,
- scenario-based offline/online crack-time estimation.

This project is designed for **password strength evaluation**, not as a standalone authentication defense system.

## Features

- Strength tiers: `Very Weak`, `Weak`, `Moderate`, `Strong`
- Breach status via Have I Been Pwned (Pwned Passwords API)
- Dual attack modeling:
  - random brute-force model
  - pattern-aware model
- Optional guessability model:
  - uses `zxcvbn` when installed
  - falls back to internal heuristics otherwise
- Conservative estimation:
  - chooses the fastest plausible crack path across models
- All-scenario mode:
  - tests all combinations of:
    - offline hash profiles
    - attacker scale profiles
    - online defense profiles
- Confidence band reporting:
  - best / expected / worst windows

## Project Structure

```text
.
├─ sila.py              # Facade + main entrypoint
├─ sila_cli.py          # Terminal UI / workflow
├─ sila_analysis.py     # Strength labels, verdict logic, explanation output
├─ sila_models.py       # Entropy, timing, pattern and guess models
├─ sila_breach.py       # HIBP + dictionary loading
├─ sila_config.py       # Constants, profiles, wordlist loading
├─ wordlists/
│  ├─ common_passwords.txt
│  └─ common_words.txt
└─ test_sila.py         # Unit tests
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

Run:

```bash
python sila.py
```

The app will:
1. Print active guessability engine (`zxcvbn` or `pattern_fallback`)
2. Test all configured scenario combinations
3. Ask for comma-separated target passwords
4. Show a concise results table
5. Show a detailed explanation panel for the first target

## Configuration

Edit `sila_config.py` for:
- NIST baseline length (`NIST_MIN_LENGTH`)
- hash profiles (`HASH_PROFILES`)
- attacker scale (`ATTACKER_SCALE`)
- online defense rates (`ONLINE_DEFENSE`)

Edit `wordlists/` for:
- `common_passwords.txt`
- `common_words.txt`

Files are loaded at runtime with fallback defaults if missing.

## Output Interpretation

- **Offline Fastest**: fastest expected crack time across all offline scenarios.
- **Online Fastest**: fastest expected crack time across all online scenarios.
- **Conservative estimate**: fastest plausible result across random/pattern/guessability models.
- **Assumption-locked estimate**: expected times under explicit profile assumptions.

## Testing

Run tests:

```bash
python -m unittest -v
```

## Notes and Limits

- This tool estimates password strength/risk; it cannot provide exact crack-time guarantees.
- Real-world security still depends on operational controls:
  - MFA
  - rate limiting / lockouts
  - secure hashing parameters
  - monitoring and incident response

## License

Add your preferred license here (MIT, Apache-2.0, etc.).
