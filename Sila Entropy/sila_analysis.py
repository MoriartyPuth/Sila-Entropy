import re

from sila_config import (
    DEFAULT_ATTACKER_PROFILE,
    DEFAULT_HASH_PROFILE,
    DEFAULT_ONLINE_DEFENSE,
    LEET_MAP,
    LOCAL_THREAT_TERMS,
    NIST_MIN_LENGTH,
)
from sila_models import (
    calculate_bruteforce_time,
    calculate_bruteforce_window,
    estimate_pattern_guess_window,
    get_conservative_window,
    get_offline_guesses_per_second,
    get_online_guesses_per_second,
    guesses_to_time_window,
)


def calculate_ete(entropy):
    """Backward-compatible offline estimate."""
    return calculate_bruteforce_time(entropy, get_offline_guesses_per_second())


def summarize_breach_status(leak_result):
    """Format breach status text for display."""
    if leak_result["status"] == "error":
        return "[yellow]Unknown (API error)[/yellow]"
    if leak_result["count"] > 0:
        return f"[red]Pwned({leak_result['count']})[/red]"
    return "[green]Clean[/green]"


def get_strength_label(password, entropy, leak_result, conservative_offline_seconds):
    """Tiered strength verdict for user-friendly output."""
    if leak_result["status"] != "ok":
        return "[red]Very Weak[/red]"
    if leak_result["count"] > 0:
        return "[red]Very Weak[/red]"

    if conservative_offline_seconds < 86400:
        tier = "Very Weak"
    elif conservative_offline_seconds < 30 * 86400:
        tier = "Weak"
    elif conservative_offline_seconds < 2 * 31536000:
        tier = "Moderate"
    else:
        tier = "Strong"

    if len(password) < NIST_MIN_LENGTH and tier in ("Moderate", "Strong"):
        tier = "Weak"

    if tier == "Strong":
        return "[green]Strong[/green]"
    if tier == "Moderate":
        return "[yellow]Moderate[/yellow]"
    if tier == "Weak":
        return "[red]Weak[/red]"
    return "[bold red]Very Weak[/bold red]"


def contains_khmer_dictionary_term(password, khmer_dict):
    """Detect local threat terms using token-based matching."""
    local_terms = set(LOCAL_THREAT_TERMS)
    dictionaries = set(local_terms)
    if khmer_dict:
        dictionaries.update(khmer_dict)
    if not dictionaries:
        return False

    normalized = password.lower().translate(LEET_MAP)
    tokens = [t for t in re.split(r"[^\w\u1780-\u17FF]+", normalized) if t]
    if any(token in dictionaries for token in tokens):
        return True
    # Fallback substring check for compact variants like "phnompenhcity".
    return any(term in normalized for term in local_terms if len(term) >= 5)


def precompute_password_models(password, entropy):
    """Compute model inputs once and reuse across scenario permutations."""
    pattern_guesses = estimate_pattern_guess_window(password, entropy)
    guessability = estimate_guessability_guess_window(password, pattern_guesses)
    return pattern_guesses, guessability


def build_attack_assessment_with_components(
    entropy,
    offline_rate,
    online_rate,
    pattern_guesses,
    guessability,
):
    """Build attack assessment from precomputed model components."""
    offline_random = calculate_bruteforce_window(entropy, offline_rate)
    online_random = calculate_bruteforce_window(entropy, online_rate)
    offline_pattern = guesses_to_time_window(pattern_guesses, offline_rate)
    online_pattern = guesses_to_time_window(pattern_guesses, online_rate)
    offline_guessability = guesses_to_time_window(guessability, offline_rate)
    online_guessability = guesses_to_time_window(guessability, online_rate)
    offline_conservative = get_conservative_window(
        get_conservative_window(offline_random, offline_pattern),
        offline_guessability,
    )
    online_conservative = get_conservative_window(
        get_conservative_window(online_random, online_pattern),
        online_guessability,
    )

    driver_candidates = {
        "Random": offline_random["expected_seconds"],
        "Pattern": offline_pattern["expected_seconds"],
        "Guessability": offline_guessability["expected_seconds"],
    }
    model_driver = min(driver_candidates, key=driver_candidates.get)

    return {
        "offline_random": offline_random,
        "online_random": online_random,
        "pattern_guesses": pattern_guesses,
        "offline_pattern": offline_pattern,
        "online_pattern": online_pattern,
        "guessability": guessability,
        "offline_guessability": offline_guessability,
        "online_guessability": online_guessability,
        "offline_conservative": offline_conservative,
        "online_conservative": online_conservative,
        "model_driver": model_driver,
    }


def build_attack_assessment(
    password,
    entropy,
    hash_profile=DEFAULT_HASH_PROFILE,
    attacker_profile=DEFAULT_ATTACKER_PROFILE,
    online_defense=DEFAULT_ONLINE_DEFENSE,
):
    """Compute random/pattern/conservative attack windows."""
    offline_rate = get_offline_guesses_per_second(
        hash_profile=hash_profile, attacker_profile=attacker_profile
    )
    online_rate = get_online_guesses_per_second(defense_profile=online_defense)
    pattern_guesses, guessability = precompute_password_models(password, entropy)

    return build_attack_assessment_with_components(
        entropy=entropy,
        offline_rate=offline_rate,
        online_rate=online_rate,
        pattern_guesses=pattern_guesses,
        guessability=guessability,
    )


def estimate_guessability_guess_window(password, pattern_guesses):
    """Estimate guessability using zxcvbn if available, else pattern fallback."""
    try:
        from zxcvbn import zxcvbn  # type: ignore

        result = zxcvbn(password)
        guesses = max(float(result.get("guesses", 1)), 1.0)
        score = int(result.get("score", 0))
        return {
            "source": "zxcvbn",
            "score": score,
            "feedback": result.get("feedback", {}),
            "low_guesses": max(1.0, guesses * 0.5),
            "expected_guesses": guesses,
            "high_guesses": guesses * 2.0,
        }
    except Exception:
        expected = max(float(pattern_guesses["expected_guesses"]), 1.0)
        # Map pattern risk (higher=weaker) to zxcvbn-like score (0 weakest .. 4 strongest).
        risk = int(pattern_guesses.get("risk_score", 0))
        if risk >= 10:
            score = 0
        elif risk >= 7:
            score = 1
        elif risk >= 4:
            score = 2
        elif risk >= 2:
            score = 3
        else:
            score = 4
        return {
            "source": "pattern_fallback",
            "score": score,
            "feedback": {},
            "low_guesses": max(1.0, expected * 0.5),
            "expected_guesses": expected,
            "high_guesses": expected * 2.0,
        }


def get_guessability_engine_name():
    """Return active guessability engine name."""
    try:
        from zxcvbn import zxcvbn  # type: ignore # noqa: F401

        return "zxcvbn"
    except Exception:
        return "pattern_fallback"


def format_confidence_band(window):
    """Format best/expected/worst values from a time window."""
    return (
        f"best {window['low']} | "
        f"expected {window['expected']} | "
        f"worst {window['high']}"
    )


def get_expert_analysis(
    password,
    entropy,
    leak_result,
    is_khmer,
    hash_profile=DEFAULT_HASH_PROFILE,
    attacker_profile=DEFAULT_ATTACKER_PROFILE,
    online_defense=DEFAULT_ONLINE_DEFENSE,
):
    """Generate an explanation of the security posture."""
    reasons = []

    if entropy > 100:
        reasons.append(
            "[green][OK] ENTROPY:[/green] High randomness against modern brute-force attacks."
        )
    else:
        reasons.append(f"[red][FAIL] ENTROPY:[/red] Lower randomness ({entropy} bits).")

    if len(password) >= NIST_MIN_LENGTH:
        reasons.append(
            f"[green][OK] NIST LENGTH:[/green] Meets the {NIST_MIN_LENGTH}-character baseline."
        )
    else:
        reasons.append(
            f"[red][FAIL] NIST LENGTH:[/red] Under {NIST_MIN_LENGTH} characters."
        )

    if leak_result["status"] == "error":
        reasons.append("[yellow][WARN] BREACH CHECK:[/yellow] HIBP lookup failed. Status unknown.")
    elif leak_result["count"] == 0:
        reasons.append("[green][OK] BREACH:[/green] No matches found in known leak corpus.")
    else:
        reasons.append(
            f"[bold red][FAIL] PWNED:[/bold red] Found {leak_result['count']} times in leak data."
        )

    if is_khmer:
        reasons.append("[red][FAIL] LOCAL THREAT:[/red] Contains a known Khmer dictionary token.")
    else:
        reasons.append("[green][OK] LOCAL THREAT:[/green] No Khmer dictionary token match detected.")

    assessment = build_attack_assessment(
        password,
        entropy,
        hash_profile=hash_profile,
        attacker_profile=attacker_profile,
        online_defense=online_defense,
    )

    strength_label = get_strength_label(
        password,
        entropy,
        leak_result,
        assessment["offline_conservative"]["expected_seconds"],
    )
    reasons.append(f"[cyan]STRENGTH:[/cyan] {strength_label}")
    reasons.append(
        "[cyan]CONSERVATIVE (Expected):[/cyan] "
        f"Offline {assessment['offline_conservative']['expected']} | "
        f"Online {assessment['online_conservative']['expected']}"
    )
    reasons.append(
        "[cyan]RANDOM MODEL (Expected):[/cyan] "
        f"Offline {assessment['offline_random']['expected']} | "
        f"Online {assessment['online_random']['expected']}"
    )
    reasons.append(
        "[cyan]PATTERN MODEL (Expected):[/cyan] "
        f"Offline {assessment['offline_pattern']['expected']} | "
        f"Online {assessment['online_pattern']['expected']}"
    )
    reasons.append(
        "[cyan]GUESSABILITY MODEL (Expected):[/cyan] "
        f"Offline {assessment['offline_guessability']['expected']} | "
        f"Online {assessment['online_guessability']['expected']} | "
        f"source={assessment['guessability']['source']} score={assessment['guessability']['score']}"
    )
    reasons.append(
        "[cyan]RANGE (25%-100%):[/cyan] "
        f"Offline {assessment['offline_conservative']['low']} to {assessment['offline_conservative']['high']} | "
        f"Online {assessment['online_conservative']['low']} to {assessment['online_conservative']['high']}"
    )
    reasons.append(
        "[cyan]CONFIDENCE BAND (Best/Expected/Worst):[/cyan] "
        f"Offline {format_confidence_band(assessment['offline_conservative'])} | "
        f"Online {format_confidence_band(assessment['online_conservative'])}"
    )
    reasons.append(
        "[cyan]ASSUMPTION-LOCKED ESTIMATE:[/cyan] "
        f"Under hash={hash_profile}, attacker={attacker_profile}, online={online_defense}, "
        f"expected crack time is Offline {assessment['offline_conservative']['expected']} and "
        f"Online {assessment['online_conservative']['expected']}."
    )
    if assessment["pattern_guesses"]["findings"]:
        reasons.append(
            "[cyan]PATTERN FLAGS:[/cyan] "
            + ", ".join(assessment["pattern_guesses"]["findings"])
        )

    is_safe = (
        len(password) >= NIST_MIN_LENGTH
        and leak_result["status"] == "ok"
        and leak_result["count"] == 0
        and "Strong" in strength_label
    )
    verdict = "[bold green]SAFE[/bold green]" if is_safe else "[bold red]UNSAFE[/bold red]"

    return verdict, reasons


def mask_secret(password):
    """Return a non-sensitive display value for a password."""
    if not password:
        return "<empty>"
    return f"<hidden:{len(password)} chars>"
