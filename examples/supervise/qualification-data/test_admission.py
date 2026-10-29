"""Intentionally flawed qualification input; repair the functions, retain tests."""

import unittest


def can_admit(ceiling, consumed, reserved, estimate):
    return consumed + estimate <= ceiling


def observed_floor(previous, cumulative):
    return previous + cumulative


class AdmissionContract(unittest.TestCase):
    def test_outstanding_reservations_count(self):
        self.assertFalse(can_admit(100, 0, 60, 60))
        self.assertTrue(can_admit(100, 20, 30, 50))

    def test_cumulative_observations_are_not_deltas(self):
        floor = 0
        for notice in (20, 35, 35, 40):
            floor = observed_floor(floor, notice)
        self.assertEqual(floor, 40)
        self.assertEqual(observed_floor(40, 35), 40)
