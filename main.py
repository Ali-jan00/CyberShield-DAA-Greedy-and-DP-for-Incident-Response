"""Run the whole project: worked example, extension case, sensitivity test,
edge cases and a timing comparison.   Usage:  python main.py"""
from __future__ import annotations

import random
import time

import edge_cases as ec
from algorithms import (Host, Link, connectivity, greedy_density, incremental_update,
                        kruskal, mark_compromised, solve_multi_knapsack)
from pipeline import (load_dataset, print_part_a, print_part_b, remove_hosts,
                      run_pipeline, top_critical)


def banner(text):
    print("\n" + "=" * 72 + f"\n{text}\n" + "=" * 72)


def worked_example():
    banner("PART C  WORKED EXAMPLE  (12 hosts, 25 links, 3 windows, 15 tasks)")
    hosts, links, windows, tasks = load_dataset()
    print(f"hosts={len(hosts)} links={len(links)} "
          f"(compromised: {', '.join(l.id for l in links if l.compromised)}) "
          f"windows={windows} tasks={len(tasks)}\n")
    res = run_pipeline(hosts, links, windows, tasks)
    print_part_a(res, hosts)
    print()
    print_part_b(res)
    return hosts, links, windows, tasks, res


def extension_case(hosts, links, res):
    banner("EXTENSION CASE  three more links become compromised: L06, L25, L09")
    new_ids = ["L06", "L25", "L09"]
    before = res["forest"]
    after_inc, stats = incremental_update(hosts, links, before, new_ids)
    after_full = kruskal(hosts, mark_compromised(links, new_ids))
    same = {e.id for e in after_inc} == {e.id for e in after_full}
    print(f"  forest edges removed: {sorted({e.id for e in before} - {e.id for e in after_inc})}")
    print(f"  forest edges added:   {sorted({e.id for e in after_inc} - {e.id for e in before})}")
    print(f"  cost before: {sum(e.cost for e in before)}   after: {sum(e.cost for e in after_inc)}")
    print(f"  incremental result identical to full recomputation: {same}")
    print(f"  incremental work: {stats['edges_scanned']} link checks for "
          f"{stats['removed_in_forest']} removed tree links "
          f"(a full rerun sorts all {len(links) - 6} usable links)")


def sensitivity(hosts, links, windows, tasks, base):
    banner("SENSITIVITY TEST  remove the two highest-criticality hosts")
    gone = top_critical(hosts, 2)
    print("  removed: " + ", ".join(f"{h.name} (criticality {h.crit})" for h in gone) + "\n")
    h2, l2, t2 = remove_hosts(hosts, links, tasks, [h.id for h in gone])
    res = run_pipeline(h2, l2, windows, t2)
    print_part_a(res, h2, "PART A  after removal")
    print()
    print_part_b(res, "PART B  after removal")
    print(f"\n  backbone cost {base['backbone_cost']} -> {res['backbone_cost']};  "
          f"risk reduction {base['dp'].value} -> {res['dp'].value}")


def edge_case_demos():
    banner("EDGE CASE 1  disconnected network")
    hosts, links = ec.disconnected_case()
    forest = kruskal(hosts, links)
    bb, other, reach, iso = connectivity(hosts, forest)
    print("  backbone:", [f"{e.id}({hosts[e.u].name}-{hosts[e.v].name})" for e in bb])
    print("  other trees (minimum spanning forest):",
          [f"{e.id}({hosts[e.u].name}-{hosts[e.v].name})" for e in other])
    print("  isolated hosts:", ", ".join(h.name for h in iso))

    banner("EDGE CASE 2  equal-cost links (tie-breaking by criticality)")
    hosts, links = ec.tie_case()
    forest = kruskal(hosts, links)
    print("  all links cost 5; chosen order:",
          [f"{e.id}({hosts[e.u].name}-{hosts[e.v].name})" for e in forest])

    banner("EDGE CASE 3  over-demand (32 h of work, 10 h of capacity)")
    tasks, caps = ec.over_demand_case()
    r = solve_multi_knapsack(tasks, caps)
    print(f"  windows {caps}; total task effort {sum(t.effort for t in tasks)} h")
    for j, lst in enumerate(r.assignment, 1):
        print(f"  W{j}: {[t.id for t in lst]} ({r.loads[j-1]}/{caps[j-1]} h)")
    print(f"  best partial value: {r.value};  left unscheduled: {[t.id for t in r.unassigned]}")

    banner("EDGE CASE 4  task longer than every window")
    tasks, caps = ec.too_heavy_case()
    r = solve_multi_knapsack(tasks, caps)
    print(f"  windows {caps}")
    print(f"  excluded: {[(t.id, t.effort) for t in r.excluded]}")
    for j, lst in enumerate(r.assignment, 1):
        print(f"  W{j}: {[t.id for t in lst]}")
    print(f"  value: {r.value}")


def benchmark(n=200, m=20000, repeats=20, seed=7):
    banner(f"BENCHMARK  incremental update vs full recomputation (n={n}, m={m})")
    rnd = random.Random(seed)
    hosts = {f"N{i}": Host(f"N{i}", f"node{i}", "x", rnd.randint(1, 500),
                           rnd.randint(1, 10), i == 0) for i in range(n)}
    ids = list(hosts)
    links = [Link(f"E{i}", ids[i], ids[i + 1], rnd.randint(1, 50)) for i in range(n - 1)]
    while len(links) < m:
        a, b = rnd.sample(ids, 2)
        links.append(Link(f"E{len(links)}", a, b, rnd.randint(1, 50)))
    forest = kruskal(hosts, links)
    victims = [e.id for e in forest[:3]]
    updated = mark_compromised(links, victims)

    t0 = time.perf_counter()
    for _ in range(repeats):
        full = kruskal(hosts, updated)
    t_full = (time.perf_counter() - t0) / repeats * 1000
    t0 = time.perf_counter()
    for _ in range(repeats):
        inc, stats = incremental_update(hosts, links, forest, victims)
    t_inc = (time.perf_counter() - t0) / repeats * 1000
    same = {e.id for e in inc} == {e.id for e in full}
    print(f"  full recomputation : {t_full:7.3f} ms")
    print(f"  incremental update : {t_inc:7.3f} ms   ({stats['edges_scanned']} link scans)")
    print(f"  identical forests  : {same}")
    print(f"  speed-up: {t_full / t_inc:.1f}x  (incremental is O(k(n+m)) for k removed tree links;"
          " full rerun is O(m log m))")


if __name__ == "__main__":
    hosts, links, windows, tasks, res = worked_example()
    extension_case(hosts, links, res)
    sensitivity(hosts, links, windows, tasks, res)
    edge_case_demos()
    benchmark()
