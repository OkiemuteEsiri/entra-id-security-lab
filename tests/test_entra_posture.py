import unittest

from src.entra_posture import analyze, score_identity


class EntraPostureTests(unittest.TestCase):
    def test_privileged_identity_without_mfa_is_high_risk(self):
        result = score_identity({
            "id": "USR-X",
            "display_name": "Test Admin",
            "type": "user",
            "roles": ["Global Administrator"],
            "mfa_enabled": False,
            "conditional_access_covered": True,
            "inactive_days": 0,
        })
        self.assertGreaterEqual(result["score"], 65)
        self.assertIn(result["severity"], {"high", "critical"})

    def test_low_risk_reader_stays_low(self):
        result = score_identity({
            "id": "USR-Y",
            "display_name": "Reader",
            "type": "user",
            "roles": ["Security Reader"],
            "mfa_enabled": True,
            "conditional_access_covered": True,
            "inactive_days": 1,
        })
        self.assertEqual(result["severity"], "low")

    def test_analysis_orders_highest_score_first(self):
        results = analyze([
            {
                "id": "A",
                "display_name": "Low",
                "type": "user",
                "roles": [],
                "mfa_enabled": True,
                "conditional_access_covered": True,
                "inactive_days": 0,
            },
            {
                "id": "B",
                "display_name": "Admin",
                "type": "user",
                "roles": ["Global Administrator"],
                "mfa_enabled": False,
                "conditional_access_covered": False,
                "inactive_days": 90,
            },
        ])
        self.assertEqual(results[0]["id"], "B")


if __name__ == "__main__":
    unittest.main()
