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
    ONLINE_DEFENSE,
)


def get_metrics(password):
    """Calculate estimated entropy and coarse compliance status."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    if any("\u1780" <= c <= "\u17FF" for c in password):
        pool += 74

    entropy = round(len(password) * math.log2(pool), 2) if pool > 0 else 0.0

    if entropy >= 128:
        status, color = "High-Assurance", "green"
    elif entropy >= 64:
        status, color = "Standard", "yellow"
    else:
        status, color = "Non-Compliant", "red"

    return entropy, status, color


def format_duration(seconds):
    """Format seconds in compact human-readable units."""
    if seconds < 1:
        return "Instant"
    if seconds < 3600:
        return f"{seconds / 60:.2f}mn"
    if seconds < 86400:
        return f"{seconds / 3600:.2f}h"
    if seconds < 2592000:
        return f"{seconds / 86400:.2f}d"
    if seconds < 31536000:
        return f"{seconds / 2592000:.2f}m"
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
    digits = "".join(c for c in password if c.isdigit())
    if len(digits) < min_len:
        return False
    for i in range(len(digits) - min_len + 1):
        chunk = digits[i : i + min_len]
        asc = "".join(str((int(chunk[0]) + j) % 10) for j in range(min_len))
        desc = "".join(str((int(chunk[0]) - j) % 10) for j in range(min_len))
        if chunk == asc or chunk == desc:
            return True
    return False


def analyze_pattern_risk(password, extra_dict=None):
    """Heuristic risk analysis used by pattern-aware cracking model."""
    lower = password.lower()
    normalized = lower.translate(LEET_MAP)
    tokens = [t for t in re.split(r"[^\w\u1780-\u17FF]+", normalized) if t]
    dictionaries = set(COMMON_WORDS)
    if extra_dict:
        dictionaries.update(extra_dict)

    findings = []
    score = 0

    if normalized in COMMON_PASSWORDS:
        score += 8
        findings.append("common_password")
    if any(t in dictionaries for t in tokens):
        score += 4
        findings.append("dictionary_token")
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
    if any(k in normalized for k in ("qwerty", "asdf", "zxcv", "1q2w", "q1w2")):
        score += 3
        findings.append("keyboard_walk")

    return {"score": score, "findings": findings}


def estimate_pattern_guess_window(password, entropy, extra_dict=None):
    """Pattern-aware guess estimates (attempt counts, not full keyspace brute force)."""
    risk = analyze_pattern_risk(password, extra_dict=extra_dict)
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
        expected = min(full_keyspace * 0.5, 1e16)
        low = max(expected * 0.5, 1e8)
        high = min(expected * 2.0, full_keyspace)

    low = min(low, full_keyspace)
    expected = min(expected, full_keyspace)
    high = min(max(high, expected), full_keyspace)

    return {
        "risk_score": score,
        "findings": risk["findings"],
        "low_guesses": low,
        "expected_guesses": expected,
        "high_guesses": high,
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
