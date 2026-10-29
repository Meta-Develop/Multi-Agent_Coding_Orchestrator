"""Intentionally flawed qualification input; repair the functions, retain tests."""

import unittest


def can_admit(ceiling, consumed, reserved, estimate):
    return consumed + estimate <= ceiling


def observed_floor(previous, cumulative):
    return previous + cumulative


def settle(state, reservation_id, cumulative):
    state["consumed"] += cumulative or 0
    state["active"].pop(reservation_id)


class LedgerContract(unittest.TestCase):
    def test_admission_counts_reservations(self):
        self.assertFalse(can_admit(100, 0, 60, 60))
        self.assertTrue(can_admit(100, 20, 30, 50))

    def test_cumulative_floor(self):
        floor = 0
        for notice in (20, 35, 35, 40):
            floor = observed_floor(floor, notice)
        self.assertEqual(floor, 40)
        self.assertEqual(observed_floor(40, 35), 40)

    def test_settlement_replay(self):
        state = {"consumed": 0, "active": {"A": 60}, "settled": {}}
        settle(state, "A", 40)
        settle(state, "A", 40)
        self.assertEqual(state["consumed"], 40)
        self.assertEqual(state["active"], {})
        self.assertEqual(state["settled"], {"A": 40})
        with self.assertRaises(ValueError):
            settle(state, "A", 41)
        self.assertEqual(state["consumed"], 40)
        self.assertEqual(state["active"], {})
        self.assertEqual(state["settled"], {"A": 40})

    def test_unknown_usage(self):
        state = {"consumed": 0, "active": {"A": 60}, "settled": {}}
        with self.assertRaises(ValueError):
            settle(state, "A", None)
        self.assertEqual(state["active"], {"A": 60})
