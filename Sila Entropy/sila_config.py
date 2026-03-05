from pathlib import Path

NIST_MIN_LENGTH = 15  # NIST 800-63B Rev. 4 baseline used by this tool
HIBP_ENDPOINT = "https://api.pwnedpasswords.com/range/"

# Attack model profiles. Tune these values to your environment.
HASH_PROFILES = {
    "sha1_fast": 5e10,
    "sha256_fast": 2e10,
    "bcrypt_12": 5e4,
    "scrypt_strong": 1e4,
    "argon2id_strong": 5e3,
}
ATTACKER_SCALE = {
    "single_gpu": 1,
    "small_rig": 8,
    "state_cluster": 1000,
}
ONLINE_DEFENSE = {
    "no_rate_limit": 50,
    "basic_rate_limit": 5,
    "strict_rate_limit": 0.3,
}

DEFAULT_HASH_PROFILE = "bcrypt_12"
DEFAULT_ATTACKER_PROFILE = "small_rig"
DEFAULT_ONLINE_DEFENSE = "strict_rate_limit"

LEET_MAP = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)

WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
COMMON_PASSWORDS_FILE = WORDLIST_DIR / "common_passwords.txt"
COMMON_WORDS_FILE = WORDLIST_DIR / "common_words.txt"


def _load_wordlist(path, fallback):
    """Load newline-separated wordlist as lowercase set."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            words = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
            return words or set(fallback)
    except OSError:
        return set(fallback)


_COMMON_PASSWORDS_FALLBACK = {
    "password",
    "password1",
    "qwerty",
    "letmein",
    "admin",
    "welcome",
    "iloveyou",
    "abc123",
    "hello123456",
    "123456",
    "123456789",
}

_COMMON_WORDS_FALLBACK = {
    "hello",
    "admin",
    "welcome",
    "password",
    "love",
    "dragon",
    "monkey",
    "football",
}

COMMON_PASSWORDS = _load_wordlist(COMMON_PASSWORDS_FILE, _COMMON_PASSWORDS_FALLBACK)
COMMON_WORDS = _load_wordlist(COMMON_WORDS_FILE, _COMMON_WORDS_FALLBACK)

BRAND_LOGO = r"""
  _____ ___ _        _      _____ _   _ _______ _____   ____  _______   __
 / ____|_ _| |      / \    | ____| \ | |__   __|  __ \ / __ \|  __ \ \ / /
| (___  | || |     / _ \   |  _| |  \| |  | |  | |__) | |  | | |__) \ V /
 \___ \ | || |    / ___ \  | |___| |\  |  | |  |  _  /| |  | |  ___/ > <
 ____) || || |___/ /   \ \ |_____|_| \_|  |_|  |_| \_\| |__| | |    / . \
|_____/|___|_____/_/     \_\                                 \____/|_| \_\
"""
