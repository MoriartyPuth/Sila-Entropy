import unittest

import sila


class TestSilaCore(unittest.TestCase):
    def test_format_duration(self):
        self.assertEqual(sila.format_duration(0.5), "Instant")
        self.assertEqual(sila.format_duration(30), "30s")
        self.assertEqual(sila.format_duration(120), "2.00min")
        self.assertEqual(sila.format_duration(60 * 60 * 24 * 45), "1.50mo")

    def test_calculate_bruteforce_time_instant(self):
        self.assertEqual(sila.calculate_bruteforce_time(0, 1e6), "Instant")

    def test_calculate_bruteforce_time_hours_and_days(self):
        # ~4.91h at 2^51 / 1e11
        self.assertTrue(sila.calculate_bruteforce_time(51, 1e11).endswith("h"))
        # ~1.02d at 2^58 / 1e11
        self.assertTrue(sila.calculate_bruteforce_time(58, 1e11).endswith("d"))

    def test_calculate_bruteforce_time_centuries(self):
        self.assertEqual(sila.calculate_bruteforce_time(80, 1e11), "Centuries")

    def test_online_vs_offline_speed(self):
        offline = sila.calculate_bruteforce_time(40, sila.get_offline_guesses_per_second())
        online = sila.calculate_bruteforce_time(40, sila.get_online_guesses_per_second())
        self.assertNotEqual(offline, "Instant")
        self.assertEqual(online, "Centuries")

    def test_bruteforce_window_order(self):
        window = sila.calculate_bruteforce_window(40, 1e11)
        # At this entropy/rate, all three values are in minutes and should differ.
        self.assertNotEqual(window["low"], window["expected"])
        self.assertNotEqual(window["expected"], window["high"])
        self.assertLess(window["low_seconds"], window["expected_seconds"])
        self.assertLess(window["expected_seconds"], window["high_seconds"])

    def test_pattern_risk_detects_hello_sequence(self):
        risk = sila.analyze_pattern_risk("hello123456789")
        self.assertGreaterEqual(risk["score"], 7)
        self.assertIn("digit_sequence", risk["findings"])

    def test_pattern_window_faster_than_random_for_weak_pattern(self):
        entropy, _, _ = sila.get_metrics("hello123456789")
        pattern = sila.estimate_pattern_guess_window("hello123456789", entropy)
        random_window = sila.calculate_bruteforce_window(
            entropy, sila.get_offline_guesses_per_second()
        )
        pattern_window = sila.guesses_to_time_window(
            pattern, sila.get_offline_guesses_per_second()
        )
        self.assertLess(
            pattern_window["expected_seconds"], random_window["expected_seconds"]
        )

    def test_khmer_token_match(self):
        khmer_dict = {"password", "\u179f\u17bd\u179f\u17d2\u178f\u17b8"}
        self.assertTrue(sila.contains_khmer_dictionary_term("my password 123", khmer_dict))
        self.assertTrue(
            sila.contains_khmer_dictionary_term(
                "abc-\u179f\u17bd\u179f\u17d2\u178f\u17b8-xyz", khmer_dict
            )
        )
        self.assertFalse(sila.contains_khmer_dictionary_term("xxpasswordyy", khmer_dict))
        self.assertTrue(sila.contains_khmer_dictionary_term("phnompenh@123", set()))

    def test_summarize_breach_error(self):
        breach = sila.summarize_breach_status({"status": "error", "count": None, "error": "timeout"})
        self.assertIn("Unknown", breach)

    def test_summarize_breach_pwned(self):
        breach = sila.summarize_breach_status({"status": "ok", "count": 12, "error": None})
        self.assertIn("Pwned(12)", breach)

    def test_summarize_breach_clean(self):
        breach = sila.summarize_breach_status({"status": "ok", "count": 0, "error": None})
        self.assertIn("Clean", breach)

    def test_strength_label(self):
        strong = sila.get_strength_label(
            "a" * 20, 100, {"status": "ok", "count": 0, "error": None}, 3 * 365 * 86400
        )
        moderate_year = sila.get_strength_label(
            "a" * 20, 100, {"status": "ok", "count": 0, "error": None}, 365 * 86400
        )
        weak_pwned = sila.get_strength_label(
            "a" * 20, 100, {"status": "ok", "count": 5, "error": None}, 365 * 86400
        )
        weak_unknown = sila.get_strength_label(
            "a" * 20, 100, {"status": "error", "count": None, "error": "timeout"}, 365 * 86400
        )
        moderate = sila.get_strength_label(
            "a" * 20, 100, {"status": "ok", "count": 0, "error": None}, 100 * 86400
        )
        weak = sila.get_strength_label(
            "a" * 20, 100, {"status": "ok", "count": 0, "error": None}, 10 * 86400
        )
        weak_fast_crack = sila.get_strength_label(
            "a" * 20, 100, {"status": "ok", "count": 0, "error": None}, 600
        )
        self.assertIn("Strong", strong)
        self.assertIn("Moderate", moderate_year)
        self.assertIn("Very Weak", weak_pwned)
        self.assertIn("Very Weak", weak_unknown)
        self.assertIn("Moderate", moderate)
        self.assertIn("Weak", weak)
        self.assertIn("Very Weak", weak_fast_crack)

    def test_profile_rates(self):
        self.assertGreater(sila.get_offline_guesses_per_second(), 0)
        self.assertGreater(sila.get_online_guesses_per_second(), 0)

    def test_confidence_band_format(self):
        band = sila.format_confidence_band(
            {"low": "1.00min", "expected": "2.00min", "high": "4.00min"}
        )
        self.assertIn("best 1.00min", band)
        self.assertIn("expected 2.00min", band)
        self.assertIn("worst 4.00min", band)

    def test_assumption_locked_line_present(self):
        verdict, reasons = sila.get_expert_analysis(
            "hello123456789",
            50,
            {"status": "ok", "count": 0, "error": None},
            False,
        )
        self.assertIn("ASSUMPTION-LOCKED ESTIMATE", "\n".join(reasons))
        self.assertTrue("SAFE" in verdict or "UNSAFE" in verdict)

    def test_guessability_window_source(self):
        pattern = {"risk_score": 8, "expected_guesses": 1e6}
        guess_window = sila.estimate_guessability_guess_window("hello123456789", pattern)
        self.assertIn(guess_window["source"], {"zxcvbn", "pattern_fallback"})
        self.assertGreaterEqual(guess_window["expected_guesses"], 1)

    def test_precomputed_assessment_matches_standard(self):
        password = "hello123456789"
        entropy, _, _ = sila.get_metrics(password)
        standard = sila.build_attack_assessment(password, entropy)
        pattern_guesses, guessability = sila.precompute_password_models(password, entropy)
        optimized = sila.build_attack_assessment_with_components(
            entropy=entropy,
            offline_rate=sila.get_offline_guesses_per_second(),
            online_rate=sila.get_online_guesses_per_second(),
            pattern_guesses=pattern_guesses,
            guessability=guessability,
        )
        self.assertEqual(
            standard["offline_conservative"]["expected"],
            optimized["offline_conservative"]["expected"],
        )
        self.assertEqual(
            standard["online_conservative"]["expected"],
            optimized["online_conservative"]["expected"],
        )

    def test_guessability_engine_name(self):
        self.assertIn(sila.get_guessability_engine_name(), {"zxcvbn", "pattern_fallback"})


CLEAN = {"status": "ok", "count": 0, "error": None}


class TestWordlists(unittest.TestCase):
    def test_local_threat_list_is_loaded(self):
        # The bundled list has ~10k romanised Khmer terms, not the 8-term fallback.
        self.assertGreater(len(sila.LOCAL_THREAT_TERMS), 5000)
        self.assertIn("battambang", sila.LOCAL_THREAT_TERMS)

    def test_khmer_script_dictionary_terms_are_kept(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "khmer_dict.txt"
            path.write_text("# comment\n\u179f\u17bd\u179f\u17d2\u178f\u17b8\nangkor\n", encoding="utf-8")
            terms = sila.load_khmer_dict(path)
        self.assertIn("\u179f\u17bd\u179f\u17d2\u178f\u17b8", terms)
        self.assertIn("angkor", terms)


class TestPatternModel(unittest.TestCase):
    def test_common_passwords_match_despite_leet_normalisation(self):
        for pw in ("123456", "password1", "Password1!", "abc123"):
            self.assertIn("common_password", sila.analyze_pattern_risk(pw)["findings"], pw)

    def test_dictionary_word_found_inside_word_plus_digits(self):
        self.assertIn("dictionary_token", sila.analyze_pattern_risk("hello2024")["findings"])
        self.assertIn("dictionary_token", sila.analyze_pattern_risk("p4ssw0rd123")["findings"])

    def test_local_term_feeds_pattern_model(self):
        risk = sila.analyze_pattern_risk("Phnom-Penh!2024")
        self.assertIn("local_threat_term", risk["findings"])
        self.assertTrue(sila.contains_khmer_dictionary_term("Phnom-Penh!2024", set()))

    def test_short_local_terms_need_whole_token(self):
        # "kep" is a local term, but must not match inside unrelated words.
        self.assertNotIn("kep", sila.find_local_threat_terms("xkepz"))
        self.assertIn("kep", sila.find_local_threat_terms("kep-2024"))

    def test_unflagged_password_uses_full_keyspace(self):
        entropy, _, _ = sila.get_metrics("Kd8#mQ2!vX9@pL5$wN3^")
        window = sila.estimate_pattern_guess_window("Kd8#mQ2!vX9@pL5$wN3^", entropy)
        self.assertEqual(window["expected_guesses"], 2 ** entropy * 0.5)

    def test_random_password_can_be_strong_and_safe(self):
        pw = "Kd8#mQ2!vX9@pL5$wN3^"
        entropy, _, _ = sila.get_metrics(pw)
        verdict, _ = sila.get_expert_analysis(
            pw, entropy, CLEAN, False, hash_profile="sha1_fast", attacker_profile="state_cluster"
        )
        self.assertTrue(sila.is_safe_verdict(verdict))


class TestNistCompliance(unittest.TestCase):
    def test_length_single_factor_vs_mfa(self):
        pw = "Kd8#mQ2!vX9@"
        self.assertEqual(sila.assess_nist_compliance(pw, CLEAN)["status"], "Non-Compliant")
        self.assertEqual(sila.assess_nist_compliance(pw, CLEAN, mfa=True)["status"], "Compliant")

    def test_blocklist_catches_decorated_common_password(self):
        result = sila.assess_nist_compliance("Password123456!!", CLEAN)
        self.assertEqual(result["status"], "Non-Compliant")
        self.assertIn(("blocklist", "fail"), [(n, s) for n, s, _ in result["checks"]])

    def test_breach_hit_and_unknown(self):
        pw = "Kd8#mQ2!vX9@pL5$wN3^"
        pwned = {"status": "ok", "count": 3, "error": None}
        error = {"status": "error", "count": None, "error": "timeout"}
        self.assertEqual(sila.assess_nist_compliance(pw, pwned)["status"], "Non-Compliant")
        self.assertEqual(sila.assess_nist_compliance(pw, error)["status"], "Unverified")
        self.assertEqual(sila.assess_nist_compliance(pw, CLEAN)["status"], "Compliant")

    def test_length_counts_code_points(self):
        # Decomposed "e" + combining accent normalises to one code point.
        self.assertEqual(sila.nist_length("e\u0301"), 1)

    def test_safe_verdict_helper(self):
        self.assertTrue(sila.is_safe_verdict("[bold green]SAFE[/bold green]"))
        self.assertFalse(sila.is_safe_verdict("[bold red]UNSAFE[/bold red]"))


class TestBreachAndCli(unittest.TestCase):
    def test_hibp_k_anonymity_and_padding(self):
        import hashlib

        digest = hashlib.sha1(b"hunter2").hexdigest().upper()

        class FakeResponse:
            text = f"{digest[5:]}:42\r\n0000000000000000000000000000000000A:0"

            def raise_for_status(self):
                pass

        class FakeSession:
            def get(self, url, headers, timeout):
                self.url, self.headers = url, headers
                return FakeResponse()

        session = FakeSession()
        result = sila.check_pwned_api("hunter2", session=session)
        self.assertEqual(result["count"], 42)
        self.assertTrue(session.url.endswith(digest[:5]))
        self.assertNotIn(digest[5:], session.url)
        self.assertEqual(session.headers["Add-Padding"], "true")

    def test_parse_targets_supports_escaped_commas(self):
        from sila_cli import parse_targets

        self.assertEqual(parse_targets(r"abc, de\,f ,, x"), ["abc", "de,f", "x"])


if __name__ == "__main__":
    unittest.main()
