import unicodedata
from pathlib import Path

# NIST SP 800-63B Rev. 4, section 3.1.1.2 (memorized secrets / passwords)
NIST_MIN_LENGTH = 15  # password used as a single-factor authenticator
NIST_MIN_LENGTH_MFA = 8  # password used only as part of multi-factor authentication
NIST_MAX_LENGTH_SUPPORTED = 64  # verifiers SHOULD allow at least this many characters

HIBP_ENDPOINT = "https://api.pwnedpasswords.com/range/"
HIBP_USER_AGENT = "SILA-Entropy-password-auditor"

# Attack model profiles (guesses/sec per GPU). Tune these values to your environment.
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

# Words specific to the service being protected (NIST "context-specific words").
# Add your system name, organisation name, etc.
CONTEXT_WORDS = {"sila", "silaentropy"}

WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
ROCKYOU_FILE = WORDLIST_DIR / "rockyou.txt"
COMMON_PASSWORDS_FILE = WORDLIST_DIR / "common_passwords.txt"
COMMON_WORDS_FILE = WORDLIST_DIR / "common_words.txt"
LOCAL_THREAT_TERMS_FILE = WORDLIST_DIR / "local_threat_terms.txt"
KHMER_DICT_FILE = WORDLIST_DIR / "khmer_dict.txt"  # optional, may contain Khmer script

# How many lines of rockyou.txt to load (it is ordered by frequency).
# None loads the whole file (~14M lines, several GB of RAM as a Python set).
ROCKYOU_MAX_WORDS = 1_000_000


def normalize_secret(text):
    """NFC-normalise and lowercase, as NIST asks verifiers to normalise Unicode."""
    return unicodedata.normalize("NFC", text).lower()


def _load_wordlist(path, fallback=(), max_words=None):
    """Load a newline-separated wordlist as a normalised set (comments with #)."""
    words = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if max_words is not None and len(words) >= max_words:
                    break
                term = line.strip()
                if not term or term.startswith("#"):
                    continue
                words.add(normalize_secret(term))
    except OSError:
        pass
    return words or set(fallback)


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

_LOCAL_THREAT_TERMS_FALLBACK = {
    "khmer",
    "cambodia",
    "kampuchea",
    "phnompenh",
    "angkor",
    "siemreap",
    "sokha",
    "chantha",
}

ROCKYOU_LOADED = ROCKYOU_FILE.exists()
COMMON_PASSWORDS = _load_wordlist(COMMON_PASSWORDS_FILE, _COMMON_PASSWORDS_FALLBACK)
if ROCKYOU_LOADED:
    COMMON_PASSWORDS |= _load_wordlist(ROCKYOU_FILE, max_words=ROCKYOU_MAX_WORDS)

COMMON_WORDS = _load_wordlist(COMMON_WORDS_FILE, _COMMON_WORDS_FALLBACK)
LOCAL_THREAT_TERMS = _load_wordlist(LOCAL_THREAT_TERMS_FILE, _LOCAL_THREAT_TERMS_FALLBACK)
LOCAL_THREAT_TERMS |= _load_wordlist(KHMER_DICT_FILE)

BRAND_LOGO = r"""
  _____ ___ _        _      _____ _   _ _______ _____   ____  _______   __
 / ____|_ _| |      / \    | ____| \ | |__   __|  __ \ / __ \|  __ \ \ / /
| (___  | || |     / _ \   |  _| |  \| |  | |  | |__) | |  | | |__) \ V /
 \___ \ | || |    / ___ \  | |___| |\  |  | |  |  _  /| |  | |  ___/ > <
 ____) || || |___/ /   \ \ |_____|_| \_|  |_|  |_| \_\| |__| | |    / . \
|_____/|___|_____/_/     \_\                                 \____/|_| \_\
"""
