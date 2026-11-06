import math
import re
import string

from sila_config import (
    ATTACKER_SCALE,
    COMMON_PASSWORDS,
    COMMON_WORDS,
    DEFAULT_ATTACKER_PROFILE,
    DEFAULT_HASH_PROFILE,
    DEFAULT_ONLINE_DEFENSE,
    HASH_PROFILES,
    LEET_MAP,
    LOCAL_THREAT_TERMS,
    ONLINE_DEFENSE,
    normalize_secret,
)

KHMER_RANGE = ("\u1780", "\u17FF")
# Letter runs (Latin or Khmer script); digits and symbols split tokens.
_WORD_RE = re.compile(r"[a-z\u1780-\u17FF]+")
# ASCII digits, whitespace and punctuation used to decorate a base word.
_DECORATION = r"[0-9\s!-/:-@\[-`{-~]"
# Local terms shorter than this only match as whole tokens, to limit false positives.
SUBSTRING_MATCH_MIN_LEN = 6


def _is_khmer(c):
    return KHMER_RANGE[0] <= c <= KHMER_RANGE[1]


def get_metrics(password):
    """Character-pool entropy (an upper bound on randomness) and a coarse grade.

    The grade is about randomness only; NIST compliance is checked separately in
    sila_analysis.assess_nist_compliance.
    """
    pool = 0
    if any(c.islower() and not _is_khmer(c) for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation or c == " " for c in password):
        pool += 33
    if any(_is_khmer(c) for c in password):
        pool += 74
    if any(ord(c) > 127 and not _is_khmer(c) for c in password):
        pool += 100  # other Unicode: rough allowance

    entropy = round(len(password) * math.log2(pool), 2) if pool > 0 else 0.0

    if entropy >= 128:
        grade, color = "High", "green"
    elif entropy >= 64:
        grade, color = "Medium", "yellow"
    else:
        grade, color = "Low", "red"

    return entropy, grade, color


def format_duration(seconds):
    """Format seconds in compact human-readable units."""
    if seconds < 1:
        return "Instant"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.2f}min"
    if seconds < 86400:
        return f"{seconds / 3600:.2f}h"
    if seconds < 2592000:
        return f"{seconds / 86400:.2f}d"
    if seconds < 31536000:
        return f"{seconds / 2592000:.2f}mo"
    if seconds > 31536000 * 100:
        return "Centuries"
    return f"{seconds / 31536000:.2f}y"


def get_offline_guesses_per_second(
    hash_profile=DEFAULT_HASH_PROFILE, attacker_profile=DEFAULT_ATTACKER_PROFILE
):
    """Compute offline guesses/sec from hash algorithm and attacker scale."""
    hash_rate = HASH_PROFILES.get(hash_profile, HASH_PROFILES[DEFAULT_HASH_PROFILE])
    scale = ATTACKER_SCALE.get(attacker_profile, ATTACKER_SCALE[DEFAULT_ATTACKER_PROFILE])
    return hash_rate * scale


def get_online_guesses_per_second(defense_profile=DEFAULT_ONLINE_DEFENSE):
    """Compute effective online guesses/sec under defense controls."""
    return ONLINE_DEFENSE.get(defense_profile, ONLINE_DEFENSE[DEFAULT_ONLINE_DEFENSE])


def estimate_attack_seconds(entropy, guesses_per_second, fraction_of_keyspace):
    """Estimate crack time for a searched fraction of keyspace."""
    attempts = (2 ** entropy) * fraction_of_keyspace
    return attempts / guesses_per_second


def calculate_bruteforce_time(entropy, guesses_per_second):
    """Return expected (50%) brute-force time for a given guess rate."""
    seconds = estimate_attack_seconds(entropy, guesses_per_second, 0.5)
    return format_duration(seconds)


def calculate_bruteforce_window(entropy, guesses_per_second):
    """Return likely crack-time window and expected value for communication."""
    low = estimate_attack_seconds(entropy, guesses_per_second, 0.25)
    expected = estimate_attack_seconds(entropy, guesses_per_second, 0.5)
    high = estimate_attack_seconds(entropy, guesses_per_second, 1.0)
    return {
        "low_seconds": low,
        "expected_seconds": expected,
        "high_seconds": high,
        "low": format_duration(low),
        "expected": format_duration(expected),
        "high": format_duration(high),
    }


def _has_digit_sequence(password, min_len=4):
    """Detect ascending/descending runs like 1234 or 9876 within a digit group."""
    for group in re.findall(r"\d+", password):
        for i in range(len(group) - min_len + 1):
            chunk = group[i : i + min_len]
            asc = "".join(str((int(chunk[0]) + j) % 10) for j in range(min_len))
            desc = "".join(str((int(chunk[0]) - j) % 10) for j in range(min_len))
            if chunk == asc or chunk == desc:
                return True
    return False


def password_variants(password):
    """Normalised forms an attacker's rules would try: as-is, de-leeted, stripped."""
    lower = normalize_secret(password)
    leet = lower.translate(LEET_MAP)
    variants = {lower, leet}
    # Base word with common suffix/prefix decoration removed ("Password1!" -> "password").
    for v in (lower, leet):
        stripped = re.sub(rf"^{_DECORATION}+|{_DECORATION}+$", "", v)
        if stripped:
            variants.add(stripped)
    return variants


def word_tokens(password):
    """Letter-run tokens from the raw and de-leeted forms ("p4ssw0rd123" -> password)."""
    lower = normalize_secret(password)
    tokens = set(_WORD_RE.findall(lower))
    tokens.update(_WORD_RE.findall(lower.translate(LEET_MAP)))
    # Leet decoding turns trailing digits into letters ("hello123" -> "helloi2e"),
    # so also try leet-decoding only the digits that sit between letters.
    inner = re.sub(
        r"(?<=[a-z])[0134578@$]+(?=[a-z])",
        lambda m: m.group(0).translate(LEET_MAP),
        lower,
    )
    tokens.update(_WORD_RE.findall(inner))
    return {t for t in tokens if len(t) >= 3}


def find_local_threat_terms(password, terms=None, extra_dict=None):
    """Return the local (Khmer/Cambodian) terms found in the password.

    Whole-token matches for every term; substring matches only for terms of
    SUBSTRING_MATCH_MIN_LEN+ characters (catches "phnompenhcity").
    """
    terms = LOCAL_THREAT_TERMS if terms is None else terms
    found = set()
    tokens = word_tokens(password)
    variants = password_variants(password)

    for collection in (terms, extra_dict or ()):
        found.update(t for t in tokens if t in collection)
        found.update(v for v in variants if v in collection)

    lower = normalize_secret(password)
    letters_only = {
        "".join(_WORD_RE.findall(lower)),
        "".join(_WORD_RE.findall(lower.translate(LEET_MAP))),
    }
    haystacks = variants | letters_only
    for term in terms:
        if len(term) >= SUBSTRING_MATCH_MIN_LEN and any(term in h for h in haystacks):
            found.add(term)
    return sorted(found)


def analyze_pattern_risk(password, extra_dict=None, local_terms=None):
    """Heuristic risk analysis used by pattern-aware cracking model."""
    variants = password_variants(password)
    tokens = word_tokens(password)
    dictionaries = set(COMMON_WORDS)
    if extra_dict:
        dictionaries.update(extra_dict)

    findings = []
    score = 0

    if any(v in COMMON_PASSWORDS for v in variants):
        score += 8
        findings.append("common_password")
    if any(t in dictionaries for t in tokens) or any(v in dictionaries for v in variants):
        score += 4
        findings.append("dictionary_token")
    if find_local_threat_terms(password, terms=local_terms):
        score += 4
        findings.append("local_threat_term")
    if _has_digit_sequence(password):
        score += 4
        findings.append("digit_sequence")
    if re.search(r"(.)\1{2,}", password):
        score += 2
        findings.append("repeated_chars")
    if re.search(r"(19|20)\d{2}", password):
        score += 2
        findings.append("year_pattern")
    if re.search(
        r"^[A-Za-z\u1780-\u17FF]+[0-9]+[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]*$",
        password,
    ):
        score += 3
        findings.append("word_plus_digits")
    lower = normalize_secret(password)
    if any(k in lower for k in ("qwerty", "asdf", "zxcv", "1q2w", "q1w2", "qazwsx")):
        score += 3
        findings.append("keyboard_walk")

    return {"score": score, "findings": findings}


def estimate_pattern_guess_window(password, entropy, extra_dict=None, local_terms=None):
    """Pattern-aware guess estimates (attempt counts, not full keyspace brute force)."""
    risk = analyze_pattern_risk(password, extra_dict=extra_dict, local_terms=local_terms)
    score = risk["score"]
    full_keyspace = 2 ** entropy

    if score >= 10:
        low, expected, high = 1e2, 1e4, 1e6
    elif score >= 7:
        low, expected, high = 1e4, 1e6, 1e8
    elif score >= 4:
        low, expected, high = 1e6, 1e8, 1e10
    elif score >= 2:
        low, expected, high = 1e8, 1e10, 1e12
    else:
        # No human pattern found: the attacker is left with brute force.
        low, expected, high = full_keyspace * 0.25, full_keyspace * 0.5, full_keyspace

    low = min(low, full_keyspace)
    expected = min(expected, full_keyspace)
    high = min(max(high, expected), full_keyspace)

    return {
        "risk_score": score,
        "findings": risk["findings"],
        "low_guesses": low,
        "expected_guesses": expected,
        "high_guesses": high,
        "bruteforce_guesses": full_keyspace * 0.5,
    }


def guesses_to_time_window(guess_window, guesses_per_second):
    """Convert guess-window estimates into time-window estimates."""
    low_seconds = guess_window["low_guesses"] / guesses_per_second
    expected_seconds = guess_window["expected_guesses"] / guesses_per_second
    high_seconds = guess_window["high_guesses"] / guesses_per_second
    return {
        "low_seconds": low_seconds,
        "expected_seconds": expected_seconds,
        "high_seconds": high_seconds,
        "low": format_duration(low_seconds),
        "expected": format_duration(expected_seconds),
        "high": format_duration(high_seconds),
    }


def get_conservative_window(random_window, pattern_window):
    """Fastest plausible path between random brute-force and pattern-aware attack."""
    low_seconds = min(random_window["low_seconds"], pattern_window["low_seconds"])
    expected_seconds = min(random_window["expected_seconds"], pattern_window["expected_seconds"])
    high_seconds = min(random_window["high_seconds"], pattern_window["high_seconds"])
    return {
        "low_seconds": low_seconds,
        "expected_seconds": expected_seconds,
        "high_seconds": high_seconds,
        "low": format_duration(low_seconds),
        "expected": format_duration(expected_seconds),
        "high": format_duration(high_seconds),
    }
