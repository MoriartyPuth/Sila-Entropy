import hashlib
from pathlib import Path

import requests

from sila_config import HIBP_ENDPOINT, HIBP_USER_AGENT, KHMER_DICT_FILE, normalize_secret


def load_khmer_dict(path=KHMER_DICT_FILE):
    """Load an optional extra local dictionary (Latin or Khmer script, one term per line)."""
    terms = set()
    candidate = Path(path)
    if not candidate.exists():
        return terms
    with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            term = normalize_secret(line.strip())
            if len(term) > 1 and not term.startswith("#"):
                terms.add(term)
    return terms


def check_pwned_api(password, session=None):
    """Check the HIBP Pwned Passwords API using k-anonymity.

    Only the first 5 hex characters of the SHA-1 hash are sent. Add-Padding hides
    the true size of the response from anyone watching the connection.
    """
    sha1_pw = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]
    http = session or requests

    try:
        response = http.get(
            f"{HIBP_ENDPOINT}{prefix}",
            headers={"Add-Padding": "true", "User-Agent": HIBP_USER_AGENT},
            timeout=5,
        )
        response.raise_for_status()

        for line in response.text.splitlines():
            if ":" not in line:
                continue
            hash_suffix, count = line.split(":", 1)
            if hash_suffix.strip().upper() == suffix:
                return {"status": "ok", "count": int(count), "error": None}

        return {"status": "ok", "count": 0, "error": None}

    except requests.RequestException as exc:
        return {"status": "error", "count": None, "error": str(exc)}
    except ValueError as exc:
        return {"status": "error", "count": None, "error": f"Parse error: {exc}"}
