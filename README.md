# Cyber Incident Response and Network Hardening System

CT-363 Design and Analysis of Algorithms, Complex Engineering Problem.
Paradigms: **Greedy (Kruskal's MST)** and **Dynamic Programming (multiple knapsack)**,
with a greedy risk-density heuristic as the bonus approximation baseline.

All data is simulated. The code does not scan, probe or touch any real network.

## Run

Python 3.8+ with no third-party packages.

    python main.py                    # worked example, extension case, sensitivity, edge cases, benchmark
    python -m unittest -v test_all    # 12 tests

`output.txt` holds a saved run of `main.py`.

## Files

| File | Purpose |
| --- | --- |
| `algorithms.py` | Kruskal + disjoint-set union, tie-break key, incremental MST update, multi-window knapsack DP with backtracking, greedy baseline, brute-force checker |
| `pipeline.py` | CSV loader, Part A -> Part B pipeline, host removal, printing |
| `edge_cases.py` | Disconnected, equal-cost, over-demand and too-heavy scenarios |
| `main.py` | Runs everything and prints the results |
| `test_all.py` | Unit tests (DP checked against brute force, incremental checked against full recomputation) |
| `data/*.csv` | 12 hosts, 25 links (3 compromised), 3 windows (6, 8, 10 h), 15 tasks |

## Model

* **Part A.** Hosts are nodes and links are weighted edges with a `compromised` flag.
  Compromised links are dropped, then Kruskal builds the cheapest trusted monitoring
  backbone from the SOC. Equal-cost links are ordered by higher combined host
  criticality, then higher combined user count, then link id (a total order, so output
  is deterministic). A disconnected network yields a minimum spanning forest and the
  unreachable hosts are listed by name.
* **Part B.** Remediation tasks (effort in hours, risk-reduction value) are packed into
  maintenance windows with distinct capacities. The DP state is the vector of remaining
  window capacities, so a task placed in one window cannot be placed in another.
  Tasks longer than every window are excluded; over-demand returns the best partial plan.
* **Pipeline.** Tasks on hosts the SOC cannot reach are deferred to out-of-band handling
  and never enter the DP.

## Complexity

| Algorithm | Time | Space |
| --- | --- | --- |
| Kruskal + DSU | O(m log m + m a(n)) = O(m log n) | O(n + m) |
| Incremental update (k removed tree links) | O(k(n + m)) | O(n + m) |
| Multi-window DP | O(n k prod(C_j + 1)) | O(n prod(C_j + 1)) |
| Brute force assignment | O((k+1)^n * n) | O(n) |

The DP is pseudo-polynomial, so keep the window count small (the code refuses tables
above 30 million cells) and discretise effort with `load_dataset(unit=...)`.

## Results on the sample data

* Backbone: 11 links, total cost 69.
* Schedule: total risk reduction 438 (DP optimum); T13 (40 h) is excluded as too long.
* Extension (L06, L25, L09 compromised): cost 69 -> 75, identical to a full recomputation.
* Sensitivity (DC01 and DB-Patient removed): cost 69 -> 62, risk reduction 438 -> 403.
