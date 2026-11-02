"""Edge-case scenarios (simulated data), shared by main.py and the tests."""
from __future__ import annotations

from algorithms import Host, Link, Task


def _h(i, name, crit=5, users=10, soc=False):
    return Host(i, name, "10.9.0.0/24", users, crit, soc)


def disconnected_case():
    """H4, H5 and H6 are only reachable through compromised links."""
    hosts = {h.id: h for h in [
        _h("A", "SOC", 8, 5, True), _h("B", "Alpha-Web"), _h("C", "Bravo-DB"),
        _h("D", "Delta-HR"), _h("E", "Echo-Print"), _h("F", "Foxtrot-Lab")]}
    links = [Link("e1", "A", "B", 3), Link("e2", "B", "C", 4),
             Link("e3", "C", "D", 5, True),     # compromised bridge
             Link("e4", "D", "E", 2),
             Link("e5", "C", "F", 6, True)]     # compromised
    return hosts, links


def tie_case():
    """Three links of equal cost: the criticality rule must choose."""
    hosts = {h.id: h for h in [
        _h("A", "SOC", 5, 5, True), _h("B", "Low-Value", 2, 50),
        _h("C", "Domain-Controller", 10, 300), _h("D", "Mid-Server", 6, 80)]}
    links = [Link("t1", "A", "B", 5), Link("t2", "A", "C", 5),
             Link("t3", "B", "C", 5), Link("t4", "C", "D", 5)]
    return hosts, links


def over_demand_case():
    tasks = [Task(f"X{i}", f"Task {i}", "ALL", w, v)
             for i, (w, v) in enumerate([(4, 50), (3, 40), (5, 55), (4, 30),
                                         (6, 62), (3, 20), (5, 35), (2, 18)], 1)]
    return tasks, [5, 5]          # 32 h of work, only 10 h available


def too_heavy_case():
    tasks = [Task("H1", "Quick patch", "ALL", 3, 30),
             Task("H2", "Rebuild the whole data centre", "ALL", 30, 500),
             Task("H3", "Rotate API keys", "ALL", 4, 45)]
    return tasks, [6, 8, 10]
