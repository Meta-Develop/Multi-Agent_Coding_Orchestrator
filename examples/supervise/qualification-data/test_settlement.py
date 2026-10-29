"""Intentionally flawed qualification input; repair completion, retain tests."""

import unittest


def complete(state, reservation_id, cumulative, persist):
    persist()
    state["consumed"] += cumulative or 0
    state["active"].pop(reservation_id)


class SettlementContract(unittest.TestCase):
    def test_failure_still_settles_once_and_replay_is_safe(self):
        state = {"consumed": 0, "active": {"A": 60}, "settled": {}}

        def fail():
            raise OSError("report unavailable")

        with self.assertRaises(OSError):
            complete(state, "A", 40, fail)
        self.assertEqual(state["consumed"], 40)
        self.assertEqual(state["active"], {})
        self.assertEqual(state["settled"], {"A": 40})
        complete(state, "A", 40, lambda: None)
        self.assertEqual(state["consumed"], 40)
        self.assertEqual(state["active"], {})
        self.assertEqual(state["settled"], {"A": 40})
        with self.assertRaises(ValueError):
            complete(state, "A", 41, lambda: self.fail("conflicting replay persisted"))
        self.assertEqual(state["consumed"], 40)
        self.assertEqual(state["active"], {})
        self.assertEqual(state["settled"], {"A": 40})

    def test_unknown_usage_is_not_zero(self):
        state = {"consumed": 0, "active": {"A": 60}, "settled": {}}
        with self.assertRaises(ValueError):
            complete(state, "A", None, lambda: None)
        self.assertEqual(state["active"], {"A": 60})
        self.assertEqual(state["settled"], {})
