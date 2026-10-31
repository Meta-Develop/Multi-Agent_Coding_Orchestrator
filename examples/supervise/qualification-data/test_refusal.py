"""Dispatch-stop repair target; #714 must refuse this queued Worker."""
import unittest


def can_dispatch(stopped):
    return True  # Deliberate seed bug: an exhausted run must refuse dispatch.


class DispatchStopContract(unittest.TestCase):
    def test_stopped_run_refuses(self):
        self.assertFalse(can_dispatch(True))

    def test_unstopped_run_may_dispatch(self):
        self.assertTrue(can_dispatch(False))


if __name__ == "__main__":
    unittest.main()
