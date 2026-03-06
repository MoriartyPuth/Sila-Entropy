import hashlib
import os
from pathlib import Path
import re

import requests

from sila_config import HIBP_ENDPOINT


def load_khmer_dict(path="khmer_dict.txt"):
    """Load optional local dictionary terms, excluding Khmer-script entries."""
    candidates = [Path(path)]
    terms = set()
    khmer_re = re.compile(r"[\u1780-\u17FF]")

    for candidate in candidates:
        if not candidate.exists():
            continue
        with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                term = line.strip().lower()
                if len(term) <= 1:
                    continue
                if khmer_re.search(term):
                    continue
                terms.add(term)

    return terms


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
