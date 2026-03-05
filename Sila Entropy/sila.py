from sila_analysis import (
    build_attack_assessment,
    calculate_ete,
    contains_khmer_dictionary_term,
    estimate_guessability_guess_window,
    format_confidence_band,
    get_expert_analysis,
    get_guessability_engine_name,
    get_strength_label,
    mask_secret,
    summarize_breach_status,
)
from sila_breach import check_pwned_api, load_khmer_dict
from sila_cli import run_audit
from sila_config import (
    ATTACKER_SCALE,
    BRAND_LOGO,
    COMMON_PASSWORDS,
    COMMON_WORDS,
    DEFAULT_ATTACKER_PROFILE,
    DEFAULT_HASH_PROFILE,
    DEFAULT_ONLINE_DEFENSE,
    HASH_PROFILES,
    HIBP_ENDPOINT,
    LEET_MAP,
    NIST_MIN_LENGTH,
    ONLINE_DEFENSE,
)
from sila_models import (
    analyze_pattern_risk,
    calculate_bruteforce_time,
    calculate_bruteforce_window,
    estimate_attack_seconds,
    estimate_pattern_guess_window,
    format_duration,
    get_conservative_window,
    get_metrics,
    get_offline_guesses_per_second,
    get_online_guesses_per_second,
    guesses_to_time_window,
)


if __name__ == "__main__":
    run_audit()
