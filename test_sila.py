import unittest

import sila


class TestSilaCore(unittest.TestCase):
    def test_format_duration(self):
        self.assertEqual(sila.format_duration(0.5), "Instant")
        self.assertEqual(sila.format_duration(120), "2.00mn")
        self.assertEqual(sila.format_duration(60 * 60 * 24 * 45), "1.50m")

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
            {"low": "1.00mn", "expected": "2.00mn", "high": "4.00mn"}
        )
        self.assertIn("best 1.00mn", band)
        self.assertIn("expected 2.00mn", band)
        self.assertIn("worst 4.00mn", band)

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

    def test_guessability_engine_name(self):
        self.assertIn(sila.get_guessability_engine_name(), {"zxcvbn", "pattern_fallback"})


if __name__ == "__main__":
    unittest.main()
