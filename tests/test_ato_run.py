import random
import unittest

import ato_run as g


class RandomIO:
    """Plays every scene by picking a random option."""
    def __init__(self, rng):
        self.rng = rng

    def run(self, s, rng, scene):
        options = scene[3]
        options[self.rng.randrange(len(options))][2](s, rng)

    def final(self, s):
        pass


class TestPlaythroughs(unittest.TestCase):
    def test_random_games_finish(self):
        for seed in range(500):
            rng = random.Random(seed)
            s = g.play(RandomIO(rng), rng)
            self.assertTrue(s.authorized)
            self.assertEqual(s.cm_month, g.CONMON_MONTHS)
            self.assertTrue(s.event_done)
            self.assertEqual(s.count("H") if s.findings else 0, 0)
            score, verdict = g.final_score(s)
            self.assertTrue(0 <= score <= 100)
            self.assertTrue(verdict)


class TestMechanics(unittest.TestCase):
    def test_open_high_blocks_authorization(self):
        s = g.State(findings=[g.Item("H", "x")])
        self.assertEqual(g.scene_authorize(s)[1], "The agency sends the package back")

    def test_high_goes_late_after_one_skipped_month(self):
        s = g.State(vulns=[g.Item("H", "x")], trust=60)
        g.tick(s, "skip", random.Random(0))
        self.assertEqual(s.late, 1)
        self.assertEqual(s.trust, 52)
        self.assertEqual(s.shipped, 1)

    def test_highs_first_closes_highs(self):
        s = g.State(vulns=[g.Item("L", "l", age=5)] * 4 + [g.Item("H", "h")])
        g.tick(s, "sev", random.Random(0))
        self.assertEqual(s.fixed, 4)
        self.assertNotIn("h", [v.name for v in s.vulns])

    def test_late_counted_once(self):
        s = g.State(vulns=[g.Item("H", "x")])
        rng = random.Random(0)
        g.tick(s, "skip", rng)
        s.vulns = [v for v in s.vulns if v.name == "x"]
        g.tick(s, "skip", rng)
        self.assertEqual(s.late, 1)


if __name__ == "__main__":
    unittest.main()
