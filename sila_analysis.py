import unicodedata

from sila_config import (
    COMMON_PASSWORDS,
    COMMON_WORDS,
    CONTEXT_WORDS,
    DEFAULT_ATTACKER_PROFILE,
    DEFAULT_HASH_PROFILE,
    DEFAULT_ONLINE_DEFENSE,
    LOCAL_THREAT_TERMS,
    NIST_MIN_LENGTH,
    NIST_MIN_LENGTH_MFA,
    normalize_secret,
)
from sila_models import (
    calculate_bruteforce_time,
    calculate_bruteforce_window,
    estimate_pattern_guess_window,
    find_local_threat_terms,
    get_conservative_window,
    get_offline_guesses_per_second,
    get_online_guesses_per_second,
    guesses_to_time_window,
    password_variants,
)

ZXCVBN_MAX_LENGTH = 256  # zxcvbn matching gets slow on very long inputs

try:
    from zxcvbn import zxcvbn as _zxcvbn  # type: ignore
    from zxcvbn import matching as _zxcvbn_matching  # type: ignore

    # Teach zxcvbn the local (romanised Khmer / Cambodian) terms as a ranked
    # dictionary, so its guess counts reflect regional passwords too.
    _zxcvbn_matching.add_frequency_lists({"khmer_local": sorted(LOCAL_THREAT_TERMS)})
except Exception:  # zxcvbn missing or incompatible
    _zxcvbn = None


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

    if nist_length(password) < NIST_MIN_LENGTH and tier in ("Moderate", "Strong"):
        tier = "Weak"

    if tier == "Strong":
        return "[green]Strong[/green]"
    if tier == "Moderate":
        return "[yellow]Moderate[/yellow]"
    if tier == "Weak":
        return "[red]Weak[/red]"
    return "[bold red]Very Weak[/bold red]"


def contains_khmer_dictionary_term(password, khmer_dict):
    """Detect local threat terms (bundled list plus an optional extra dictionary)."""
    extra = {normalize_secret(t) for t in khmer_dict} if khmer_dict else None
    return bool(find_local_threat_terms(password, extra_dict=extra))


def nist_length(password):
    """Length as NIST counts it: Unicode code points after normalisation."""
    return len(unicodedata.normalize("NFC", password))


def assess_nist_compliance(password, leak_result, mfa=False):
    """Check a password against NIST SP 800-63B Rev. 4 section 3.1.1.2.

    Covers what can be checked from the password itself: minimum length, the
    blocklist (breached values, common passwords, dictionary words,
    context-specific words). NIST forbids composition rules, so none are applied.
    Returns {"status": Compliant | Non-Compliant | Unverified, "checks": [...]},
    each check being (name, state, detail) with state "pass", "fail" or "unknown".
    """
    checks = []
    min_len = NIST_MIN_LENGTH_MFA if mfa else NIST_MIN_LENGTH
    length = nist_length(password)
    checks.append(
        (
            "length",
            "pass" if length >= min_len else "fail",
            f"{length} chars, minimum {min_len} ({'part of MFA' if mfa else 'single-factor'})",
        )
    )

    if leak_result["status"] != "ok":
        checks.append(("breach_corpus", "unknown", "HIBP lookup failed"))
    elif leak_result["count"] > 0:
        checks.append(("breach_corpus", "fail", f"seen {leak_result['count']} times in breaches"))
    else:
        checks.append(("breach_corpus", "pass", "not in HIBP breach corpus"))

    variants = password_variants(password)
    blocklists = (
        ("common password", COMMON_PASSWORDS),
        ("dictionary word", COMMON_WORDS),
        ("local term", LOCAL_THREAT_TERMS),
    )
    hit = next((label for label, words in blocklists if variants & words), None)
    checks.append(
        (
            "blocklist",
            "fail" if hit else "pass",
            f"whole password is a {hit}" if hit else "not a common password or dictionary word",
        )
    )

    lower = normalize_secret(password)
    context_hit = any(w and w in lower for w in CONTEXT_WORDS)
    checks.append(
        (
            "context_words",
            "fail" if context_hit else "pass",
            "contains a service-specific word" if context_hit else "no service-specific words",
        )
    )

    states = {state for _, state, _ in checks}
    if "fail" in states:
        status = "Non-Compliant"
    elif "unknown" in states:
        status = "Unverified"
    else:
        status = "Compliant"
    return {"status": status, "checks": checks}


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


def _pattern_fallback_window(pattern_guesses):
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


def estimate_guessability_guess_window(password, pattern_guesses):
    """Estimate guessability using zxcvbn if available, else pattern fallback."""
    if _zxcvbn is None or len(password) > ZXCVBN_MAX_LENGTH:
        return _pattern_fallback_window(pattern_guesses)
    try:
        result = _zxcvbn(
            password,
            user_inputs=sorted(CONTEXT_WORDS),
            max_length=ZXCVBN_MAX_LENGTH,
        )
    except Exception:
        return _pattern_fallback_window(pattern_guesses)

    guesses = max(float(result.get("guesses", 1)), 1.0)
    sequence = result.get("sequence") or []
    if sequence and all(m.get("pattern") == "bruteforce" for m in sequence):
        # zxcvbn found no words or patterns; its brute-force bound (10 guesses
        # per character) badly undercounts a random password, so use the
        # character-pool keyspace like the other models do.
        guesses = max(guesses, float(pattern_guesses.get("bruteforce_guesses", guesses)))
    return {
        "source": "zxcvbn",
        "score": int(result.get("score", 0)),
        "feedback": result.get("feedback", {}),
        "low_guesses": max(1.0, guesses * 0.5),
        "expected_guesses": guesses,
        "high_guesses": guesses * 2.0,
    }


def get_guessability_engine_name():
    """Return active guessability engine name."""
    return "zxcvbn" if _zxcvbn is not None else "pattern_fallback"


def format_confidence_band(window):
    """Format best/expected/worst values from a time window."""
    return (
        f"best {window['low']} | "
        f"expected {window['expected']} | "
        f"worst {window['high']}"
    )


_NIST_STATE_STYLE = {
    "pass": "[green][OK]",
    "fail": "[red][FAIL]",
    "unknown": "[yellow][WARN]",
}
_NIST_STATE_CLOSE = {"pass": "[/green]", "fail": "[/red]", "unknown": "[/yellow]"}


def get_expert_analysis(
    password,
    entropy,
    leak_result,
    is_khmer,
    hash_profile=DEFAULT_HASH_PROFILE,
    attacker_profile=DEFAULT_ATTACKER_PROFILE,
    online_defense=DEFAULT_ONLINE_DEFENSE,
    mfa=False,
):
    """Generate an explanation of the security posture."""
    reasons = []

    if entropy > 100:
        reasons.append(
            "[green][OK] ENTROPY:[/green] High character-pool randomness "
            f"({entropy} bits, an upper bound)."
        )
    else:
        reasons.append(
            f"[red][FAIL] ENTROPY:[/red] Lower randomness ({entropy} bits, an upper bound)."
        )

    nist = assess_nist_compliance(password, leak_result, mfa=mfa)
    for name, state, detail in nist["checks"]:
        label = f"NIST {name.upper().replace('_', ' ')}"
        reasons.append(f"{_NIST_STATE_STYLE[state]} {label}:{_NIST_STATE_CLOSE[state]} {detail}")
    reasons.append(f"[cyan]NIST SP 800-63B-4:[/cyan] {nist['status']}")

    if leak_result["status"] == "ok" and leak_result["count"] > 0:
        reasons.append(
            f"[bold red][FAIL] PWNED:[/bold red] Found {leak_result['count']} times in leak data."
        )

    if is_khmer:
        reasons.append(
            "[red][FAIL] LOCAL THREAT:[/red] Contains a known Khmer/Cambodian term; "
            "crack estimates assume attackers use a regional wordlist."
        )
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
    suggestions = assessment["guessability"].get("feedback", {}).get("suggestions") or []
    if suggestions:
        reasons.append("[cyan]SUGGESTIONS:[/cyan] " + " ".join(suggestions))

    is_safe = nist["status"] == "Compliant" and "Strong" in strength_label
    verdict = "[bold green]SAFE[/bold green]" if is_safe else "[bold red]UNSAFE[/bold red]"

    return verdict, reasons


def is_safe_verdict(verdict):
    """True for the SAFE verdict string (note "SAFE" is a substring of "UNSAFE")."""
    return "UNSAFE" not in verdict and "SAFE" in verdict


def mask_secret(password):
    """Return a non-sensitive display value for a password."""
    if not password:
        return "<empty>"
    return f"<hidden:{nist_length(password)} chars>"
