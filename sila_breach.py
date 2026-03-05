import hashlib
import os

import requests

from sila_config import HIBP_ENDPOINT


def load_khmer_dict(path="khmer_dict.txt"):
    """Load Khmer dictionary terms (length > 3) from a local file."""
    if not os.path.exists(path):
        return set()

    with open(path, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if len(line.strip()) > 3}


def check_pwned_api(password):
    """Check the HIBP Pwned Passwords API using k-anonymity."""
    sha1_pw = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]

    try:
        response = requests.get(f"{HIBP_ENDPOINT}{prefix}", timeout=5)
        response.raise_for_status()

        for line in response.text.splitlines():
            if ":" not in line:
                continue
            hash_suffix, count = line.split(":", 1)
            if hash_suffix == suffix:
                return {"status": "ok", "count": int(count), "error": None}

        return {"status": "ok", "count": 0, "error": None}

    except requests.RequestException as exc:
        return {"status": "error", "count": None, "error": str(exc)}
    except ValueError as exc:
        return {"status": "error", "count": None, "error": f"Parse error: {exc}"}
