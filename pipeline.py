"""Integrated pipeline: Part A (greedy backbone) feeds Part B (DP scheduling)."""
from __future__ import annotations

import csv
import math
import os
from typing import Dict, List, Sequence

from algorithms import (Host, Link, Task, connectivity, greedy_density,
                        kruskal, solve_multi_knapsack)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def load_dataset(data_dir: str = DATA_DIR, unit: float = 1.0):
    """Read the four CSV files. `unit` discretises effort (rounded up) and
    window capacity (rounded down), e.g. unit=0.5 for half-hour blocks."""
    def rows(name):
        with open(os.path.join(data_dir, name), newline="") as f:
            return list(csv.DictReader(f))

    hosts = {r["id"]: Host(r["id"], r["name"], r["subnet"], int(r["users"]),
                           int(r["criticality"]), r["soc"] == "1")
             for r in rows("hosts.csv")}
    links = [Link(r["id"], r["u"], r["v"], int(r["cost"]), r["compromised"] == "1")
             for r in rows("links.csv")]
    windows = [int(float(r["capacity_hours"]) // unit) for r in rows("windows.csv")]
    tasks = [Task(r["id"], r["name"], r["host"],
                  math.ceil(float(r["effort_hours"]) / unit), int(r["risk_reduction"]))
             for r in rows("tasks.csv")]
    return hosts, links, windows, tasks


def remove_hosts(hosts: Dict[str, Host], links: Sequence[Link],
                 tasks: Sequence[Task], ids):
    ids = set(ids)
    return ({h: v for h, v in hosts.items() if h not in ids},
            [l for l in links if l.u not in ids and l.v not in ids],
            [t for t in tasks if t.host not in ids])


def top_critical(hosts: Dict[str, Host], count: int = 2) -> List[Host]:
    """Highest-criticality non-SOC hosts (ties: more users, then id)."""
    cand = [h for h in hosts.values() if not h.soc]
    return sorted(cand, key=lambda h: (-h.crit, -h.users, h.id))[:count]


def run_pipeline(hosts, links, windows, tasks):
    """Part A then Part B. Tasks on hosts the SOC cannot reach are deferred
    to out-of-band handling, so the DP only sees reachable work."""
    forest = kruskal(hosts, links)
    backbone, other, reachable, isolated = connectivity(hosts, forest)
    eligible = [t for t in tasks if t.host == "ALL" or t.host in reachable]
    deferred = [t for t in tasks if t not in eligible]
    dp = solve_multi_knapsack(eligible, windows)
    greedy = greedy_density(eligible, windows)
    return {"forest": forest, "backbone": backbone, "other_edges": other,
            "reachable": reachable, "isolated": isolated, "eligible": eligible,
            "deferred": deferred, "dp": dp, "greedy": greedy,
            "backbone_cost": sum(e.cost for e in backbone)}


# ----------------------------------------------------------------- printing
def print_part_a(result, hosts, title="PART A  Secure monitoring backbone (Kruskal)"):
    print(title)
    print("-" * len(title))
    for e in result["backbone"]:
        print(f"  {e.id}: {hosts[e.u].name:<16} - {hosts[e.v].name:<16} cost {e.cost}")
    print(f"  backbone links: {len(result['backbone'])}   total cost: {result['backbone_cost']}")
    if result["other_edges"]:
        print("  separate trees outside the SOC component:")
        for e in result["other_edges"]:
            print(f"    {e.id}: {hosts[e.u].name} - {hosts[e.v].name} cost {e.cost}")
    if result["isolated"]:
        print("  ISOLATED hosts (not reachable from the SOC): "
              + ", ".join(h.name for h in result["isolated"]))
    else:
        print("  isolated hosts: none")


def print_part_b(result, title="PART B  Remediation schedule (multi-window DP)"):
    dp, gr = result["dp"], result["greedy"]
    print(title)
    print("-" * len(title))
    for j, (cap, load, lst) in enumerate(zip(dp.capacities, dp.loads, dp.assignment), 1):
        print(f"  Window W{j} ({load}/{cap} h):")
        for t in lst:
            print(f"      {t.id} {t.name:<42} {t.effort} h  +{t.value}")
        if not lst:
            print("      (empty)")
    print(f"  total risk reduction (DP optimum): {dp.value}")
    print(f"  greedy risk-density baseline:      {gr.value}   "
          f"(gap {dp.value - gr.value}, {100 * (dp.value - gr.value) / dp.value:.1f}% of optimum)"
          if dp.value else "  greedy baseline: 0")
    if dp.excluded:
        print("  excluded (longer than every window): "
              + ", ".join(f"{t.id} ({t.effort} h)" for t in dp.excluded))
    if dp.unassigned:
        print("  left unscheduled (no capacity): "
              + ", ".join(t.id for t in dp.unassigned))
    if result["deferred"]:
        print("  deferred to out-of-band handling (host unreachable/removed): "
              + ", ".join(t.id for t in result["deferred"]))
