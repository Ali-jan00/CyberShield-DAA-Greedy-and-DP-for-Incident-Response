"""Unit tests.   Usage:  python -m unittest -v test_all"""
import random
import unittest

import edge_cases as ec
from algorithms import (Host, Link, Task, brute_force_value, connectivity,
                        greedy_density, incremental_update, kruskal,
                        mark_compromised, solve_multi_knapsack)
from pipeline import load_dataset, remove_hosts, run_pipeline, top_critical


class PartATests(unittest.TestCase):
    def test_disconnected_graph_gives_forest_and_names(self):
        hosts, links = ec.disconnected_case()
        forest = kruskal(hosts, links)
        bb, other, reach, iso = connectivity(hosts, forest)
        self.assertEqual({h.name for h in iso}, {"Delta-HR", "Echo-Print", "Foxtrot-Lab"})
        self.assertEqual([e.id for e in other], ["e4"])
        self.assertEqual({e.id for e in bb}, {"e1", "e2"})

    def test_tie_breaking_prefers_critical_hosts(self):
        hosts, links = ec.tie_case()
        ids = [e.id for e in kruskal(hosts, links)]
        # all costs equal -> order is by combined criticality: t4 (16), t2 (15), t3 (12)
        self.assertEqual(ids, ["t4", "t2", "t3"])
        # same answer whatever the input order (deterministic)
        self.assertEqual(ids, [e.id for e in kruskal(hosts, list(reversed(links)))])

    def test_main_dataset_mst_cost(self):
        hosts, links, windows, tasks = load_dataset()
        res = run_pipeline(hosts, links, windows, tasks)
        self.assertEqual(res["backbone_cost"], 69)
        self.assertEqual(len(res["backbone"]), 11)
        self.assertEqual(res["isolated"], [])

    def test_incremental_matches_full_on_dataset(self):
        hosts, links, _, _ = load_dataset()
        forest = kruskal(hosts, links)
        new = ["L06", "L25", "L09"]
        inc, stats = incremental_update(hosts, links, forest, new)
        full = kruskal(hosts, mark_compromised(links, new))
        self.assertEqual({e.id for e in inc}, {e.id for e in full})
        self.assertEqual(stats["removed_in_forest"], 3)

    def test_incremental_matches_full_fuzz(self):
        rnd = random.Random(1)
        for _ in range(200):
            n = rnd.randint(3, 12)
            hosts = {f"N{i}": Host(f"N{i}", f"n{i}", "x", rnd.randint(1, 9),
                                   rnd.randint(1, 10), i == 0) for i in range(n)}
            ids = list(hosts)
            links = [Link(f"E{i}", rnd.choice(ids), rnd.choice(ids), rnd.randint(1, 5))
                     for i in range(rnd.randint(n, 3 * n))]
            forest = kruskal(hosts, links)
            victims = rnd.sample([l.id for l in links], min(3, len(links)))
            inc, _ = incremental_update(hosts, links, forest, victims)
            full = kruskal(hosts, mark_compromised(links, victims))
            self.assertEqual({e.id for e in inc}, {e.id for e in full})


class PartBTests(unittest.TestCase):
    def test_over_demand_returns_partial_plan(self):
        tasks, caps = ec.over_demand_case()
        r = solve_multi_knapsack(tasks, caps)
        self.assertGreater(r.value, 0)
        self.assertTrue(r.unassigned)
        self.assertTrue(all(l <= c for l, c in zip(r.loads, caps)))

    def test_task_too_heavy_is_excluded(self):
        tasks, caps = ec.too_heavy_case()
        r = solve_multi_knapsack(tasks, caps)
        self.assertEqual([t.id for t in r.excluded], ["H2"])
        self.assertEqual(r.value, 75)

    def test_matches_brute_force(self):
        rnd = random.Random(2)
        for _ in range(60):
            n = rnd.randint(1, 7)
            tasks = [Task(f"T{i}", "t", "ALL", rnd.randint(1, 6), rnd.randint(1, 30))
                     for i in range(n)]
            caps = [rnd.randint(2, 7) for _ in range(rnd.randint(1, 3))]
            r = solve_multi_knapsack(tasks, caps)
            self.assertEqual(r.value, brute_force_value(tasks, caps))
            used = [t.id for lst in r.assignment for t in lst]
            self.assertEqual(len(used), len(set(used)))          # no task twice
            self.assertEqual(r.value, sum(t.value for lst in r.assignment for t in lst))

    def test_dp_beats_or_ties_greedy(self):
        hosts, links, windows, tasks = load_dataset()
        res = run_pipeline(hosts, links, windows, tasks)
        self.assertGreaterEqual(res["dp"].value, res["greedy"].value)

    def test_greedy_can_be_suboptimal(self):
        # density order picks a (10/h) first, leaving 2 h that nothing fits in
        tasks = [Task("a", "a", "ALL", 6, 60), Task("b", "b", "ALL", 4, 38),
                 Task("c", "c", "ALL", 4, 38)]
        self.assertEqual(greedy_density(tasks, [8]).value, 60)
        self.assertEqual(solve_multi_knapsack(tasks, [8]).value, 76)


class PipelineTests(unittest.TestCase):
    def test_sensitivity_removes_top_two_and_changes_outputs(self):
        hosts, links, windows, tasks = load_dataset()
        base = run_pipeline(hosts, links, windows, tasks)
        gone = top_critical(hosts, 2)
        self.assertEqual([h.name for h in gone], ["DC01", "DB-Patient"])
        h2, l2, t2 = remove_hosts(hosts, links, tasks, [h.id for h in gone])
        res = run_pipeline(h2, l2, windows, t2)
        self.assertNotEqual(res["backbone_cost"], base["backbone_cost"])
        self.assertNotEqual(res["dp"].value, base["dp"].value)
        self.assertFalse({"T01", "T03"} & {t.id for t in res["eligible"]})

    def test_unreachable_hosts_tasks_are_deferred(self):
        hosts, links, windows, tasks = load_dataset()
        res = run_pipeline(hosts, mark_compromised(links, ["L20", "L11", "L22"]), windows, tasks)
        self.assertEqual([h.name for h in res["isolated"]], ["Guest-WiFi"])
        self.assertIn("T12", {t.id for t in res["deferred"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
