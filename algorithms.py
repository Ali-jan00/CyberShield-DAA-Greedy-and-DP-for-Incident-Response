"""Core algorithms for the Cyber Incident Response and Network Hardening System.

Part A (greedy):  Kruskal's minimum spanning forest with a documented
                  tie-breaking rule, plus an incremental update when more
                  links are found compromised.
Part B (DP):      Multiple-knapsack dynamic programme (shared task usage across
                  maintenance windows) with backtracking, and a greedy
                  risk-density heuristic used as the bonus approximation
                  baseline.

All data used with this module is simulated; nothing here scans or touches a
real network.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, replace
from math import prod
from typing import Dict, Iterable, List, Sequence, Set, Tuple


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Host:
    id: str
    name: str
    subnet: str
    users: int
    crit: int          # criticality 1-10
    soc: bool = False


@dataclass(frozen=True)
class Link:
    id: str
    u: str
    v: str
    cost: int
    compromised: bool = False


@dataclass(frozen=True)
class Task:
    id: str
    name: str
    host: str          # host id, or "ALL" for organisation-wide tasks
    effort: int        # integer hours (after discretisation)
    value: int         # risk reduction, a constant taken from the input


# Part A: Kruskal with disjoint-set union
class DSU:
    """Disjoint-set union with union by rank and path compression."""

    def __init__(self, items: Iterable[str]):
        self.parent = {x: x for x in items}
        self.rank = {x: 0 for x in items}

    def find(self, x: str) -> str:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:          # path compression
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: str, b: str) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self.rank[ra] < self.rank[rb]:      # union by rank
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        return True


def edge_key(link: Link, hosts: Dict[str, Host]) -> Tuple:
    """Total order on links, which makes the result deterministic.

    1. lower cost first (the MST objective);
    2. on equal cost, higher combined host criticality first, so the most
       important assets are brought under monitoring earliest;
    3. then higher combined user count (more people protected);
    4. finally the link id, so that no two links ever compare equal.
    """
    a, b = hosts[link.u], hosts[link.v]
    return (link.cost, -(a.crit + b.crit), -(a.users + b.users), link.id)


def kruskal(hosts: Dict[str, Host], links: Sequence[Link]) -> List[Link]:
    """Minimum spanning forest over the non-compromised links.

    Compromised links are removed before the scan. If the graph is
    disconnected the scan simply ends with one tree per component.
    """
    usable = [l for l in links
              if not l.compromised and l.u in hosts and l.v in hosts]
    usable.sort(key=lambda l: edge_key(l, hosts))
    dsu = DSU(hosts.keys())
    forest: List[Link] = []
    for l in usable:
        if dsu.union(l.u, l.v):
            forest.append(l)
    return forest


def connectivity(hosts: Dict[str, Host], forest: Sequence[Link]):
    """Split a forest into the SOC backbone and the rest.

    Returns (backbone_edges, other_edges, reachable_ids, isolated_hosts)
    where isolated_hosts is sorted by name.
    """
    soc_ids = [h.id for h in hosts.values() if h.soc]
    if not soc_ids:
        raise ValueError("no SOC host (soc=1) in the host set")
    dsu = DSU(hosts.keys())
    for e in forest:
        dsu.union(e.u, e.v)
    root = dsu.find(soc_ids[0])
    reachable = {h for h in hosts if dsu.find(h) == root}
    backbone = [e for e in forest if e.u in reachable]
    other = [e for e in forest if e.u not in reachable]
    isolated = sorted((hosts[h] for h in hosts if h not in reachable),
                      key=lambda h: h.name)
    return backbone, other, reachable, isolated


def mark_compromised(links: Sequence[Link], ids: Iterable[str]) -> List[Link]:
    ids = set(ids)
    return [replace(l, compromised=True) if l.id in ids else l for l in links]


def incremental_update(hosts: Dict[str, Host], links: Sequence[Link],
                       forest: Sequence[Link], newly_compromised: Iterable[str]):
    """Update a minimum spanning forest after more links become compromised.

    * A removed link that is not in the forest changes nothing.
    * A removed forest link splits one tree in two; the new forest is the old
      one minus that link plus the cheapest usable link that crosses the cut
      (if any). This is exact for edge deletion and, because edge_key is a
      total order, gives the same forest as a full recomputation.

    Cost: O(n + m) per removed forest link, against O(m log m) for a rerun.
    Returns (new_forest, stats).
    """
    dead = {l.id for l in links if l.compromised}       # unusable links
    tree = {e.id: e for e in forest}
    stats = {"removed_in_forest": 0, "replaced": 0, "edges_scanned": 0}

    for eid in newly_compromised:
        dead.add(eid)
        if eid not in tree:
            continue
        removed = tree.pop(eid)
        stats["removed_in_forest"] += 1

        adj: Dict[str, List[str]] = {}
        for e in tree.values():
            adj.setdefault(e.u, []).append(e.v)
            adj.setdefault(e.v, []).append(e.u)
        side: Set[str] = {removed.u}
        stack = [removed.u]
        while stack:
            x = stack.pop()
            for y in adj.get(x, ()):
                if y not in side:
                    side.add(y)
                    stack.append(y)

        best, best_key = None, None
        for l in links:                                  # one O(m) pass
            stats["edges_scanned"] += 1
            if l.id in dead or l.id in tree:
                continue
            if (l.u in side) != (l.v in side):           # crosses the cut
                k = edge_key(l, hosts)                   # key only when needed
                if best is None or k < best_key:
                    best, best_key = l, k
        if best is not None:
            tree[best.id] = best
            stats["replaced"] += 1
    return list(tree.values()), stats


# Part B: multiple-knapsack dynamic programme

@dataclass
class KnapsackResult:
    value: int
    capacities: List[int]
    assignment: List[List[Task]]     # one list of tasks per window
    loads: List[int]
    excluded: List[Task]             # too long for every window
    unassigned: List[Task]           # feasible but not selected


MAX_CELLS = 30_000_000


def solve_multi_knapsack(tasks: Sequence[Task], capacities: Sequence[int]) -> KnapsackResult:
    """Exact multiple-knapsack DP over the joint remaining-capacity vector.

    State      dp[i][c1..ck] = best total value using only the first i tasks
               when window j has c_j hours available.
    Recurrence dp[i][c] = max( dp[i-1][c],
                               max over j with c_j >= w_i of
                                   dp[i-1][c - w_i * e_j] + v_i )
    Base       dp[0][.] = 0.
    Because all window capacities sit in one state, a task placed in one
    window is not available to another, which k independent knapsack runs
    would get wrong. Task values are constants read from the input.

    Tasks longer than every window are excluded first. Excess workload is
    harmless: the table simply returns the best partial plan.

    Time  O(n * k * prod(C_j + 1))     Space O(n * prod(C_j + 1))
    """
    caps = list(capacities)
    k = len(caps)
    cap_max = max(caps) if caps else 0
    feasible = [t for t in tasks if 0 < t.effort <= cap_max]
    excluded = [t for t in tasks if t not in feasible]
    empty = KnapsackResult(0, caps, [[] for _ in caps], [0] * k, excluded, list(feasible))
    if not feasible:
        return empty

    radix = [c + 1 for c in caps]
    strides = [prod(radix[j + 1:]) for j in range(k)]
    S = prod(radix)
    n = len(feasible)
    if S * (n + 1) > MAX_CELLS:
        raise ValueError(f"DP table would need {S * (n + 1):,} cells; "
                         "discretise effort/capacity into coarser units")
    states = list(itertools.product(*[range(c + 1) for c in caps]))

    dp = [[0] * S]
    for t in feasible:
        prev = dp[-1]
        cur = prev[:]                              # option: skip the task
        for idx, s in enumerate(states):
            best = cur[idx]
            for j in range(k):
                if s[j] >= t.effort:
                    cand = prev[idx - t.effort * strides[j]] + t.value
                    if cand > best:
                        best = cand
            cur[idx] = best
        dp.append(cur)

    # backtrack from the full-capacity state (last index in product order)
    idx = S - 1
    assignment: List[List[Task]] = [[] for _ in caps]
    chosen: Set[str] = set()
    for i in range(n, 0, -1):
        t = feasible[i - 1]
        if dp[i][idx] == dp[i - 1][idx]:
            continue
        s = states[idx]
        for j in range(k):
            if s[j] >= t.effort and dp[i - 1][idx - t.effort * strides[j]] + t.value == dp[i][idx]:
                assignment[j].append(t)
                chosen.add(t.id)
                idx -= t.effort * strides[j]
                break
    for lst in assignment:
        lst.reverse()
    loads = [sum(t.effort for t in lst) for lst in assignment]
    unassigned = [t for t in feasible if t.id not in chosen]
    return KnapsackResult(dp[n][S - 1], caps, assignment, loads, excluded, unassigned)


def greedy_density(tasks: Sequence[Task], capacities: Sequence[int]) -> KnapsackResult:
    """Bonus baseline: highest risk-per-hour first, best-fit window."""
    caps = list(capacities)
    cap_max = max(caps) if caps else 0
    feasible = [t for t in tasks if 0 < t.effort <= cap_max]
    excluded = [t for t in tasks if t not in feasible]
    remaining = caps[:]
    assignment: List[List[Task]] = [[] for _ in caps]
    chosen: Set[str] = set()
    order = sorted(feasible, key=lambda t: (-t.value / t.effort, t.id))
    for t in order:
        fits = [j for j in range(len(caps)) if remaining[j] >= t.effort]
        if not fits:
            continue
        j = min(fits, key=lambda j: (remaining[j], j))     # tightest window
        assignment[j].append(t)
        remaining[j] -= t.effort
        chosen.add(t.id)
    loads = [sum(t.effort for t in lst) for lst in assignment]
    value = sum(t.value for lst in assignment for t in lst)
    unassigned = [t for t in feasible if t.id not in chosen]
    return KnapsackResult(value, caps, assignment, loads, excluded, unassigned)


def brute_force_value(tasks: Sequence[Task], capacities: Sequence[int]) -> int:
    """Exhaustive (k+1)^n check, used only by the tests on tiny inputs."""
    caps = list(capacities)
    best = 0
    for choice in itertools.product(range(len(caps) + 1), repeat=len(tasks)):
        loads = [0] * len(caps)
        val = 0
        ok = True
        for t, c in zip(tasks, choice):
            if c == 0:
                continue
            loads[c - 1] += t.effort
            if loads[c - 1] > caps[c - 1]:
                ok = False
                break
            val += t.value
        if ok and val > best:
            best = val
    return best
