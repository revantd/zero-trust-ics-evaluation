#!/usr/bin/env python3
"""
05_Calculation_Code.py
Reproducible graph-based evaluation for the paper
"Zero Trust Architecture for Industrial Control Systems: A Security Framework
for Modern Critical Infrastructure" (R. Dalvi).

IMPORTANT: The network modelled here is ILLUSTRATIVE. It is not a measurement
of any real plant. Every number produced is a property of the declared model
(nodes, edges, edge-authentication attributes) and nothing else. A modelled
path means "network reachability that an attacker could attempt to use"; it is
NOT proof that an attack would succeed (exploitability is out of scope).

Usage:
    python3 05_Calculation_Code.py            # prints results, writes CSVs to data/
Requires: Python >= 3.9, networkx >= 2.6
"""
from __future__ import annotations

import csv
import itertools
import json
import os
import sys

import networkx as nx

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
os.makedirs(DATA, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. Nodes (13 assets) and zone membership
# ---------------------------------------------------------------------------
NODES = {
    # id         : (description, zone, Purdue level)
    "ENT-WS":   ("Enterprise workstation",               "Z_ENT",  "L4"),
    "VENDOR":   ("Remote vendor workstation (external)", "Z_EXT",  "External"),
    "JUMP":     ("Industrial DMZ jump server",           "Z_DMZ",  "L3.5"),
    "HIST-DMZ": ("DMZ historian replica",                "Z_DMZ",  "L3.5"),
    "HIST":     ("OT historian",                         "Z_OPS",  "L3"),
    "SCADA":    ("SCADA server",                         "Z_OPS",  "L3/L2"),
    "EWS":      ("Engineering workstation",              "Z_OPS",  "L3/L2"),
    "HMI1":     ("Operator HMI 1",                       "Z_SUP",  "L2"),
    "HMI2":     ("Operator HMI 2",                       "Z_SUP",  "L2"),
    "PLC1":     ("PLC 1 (modern)",                       "Z_CTRL", "L1"),
    "PLC2":     ("PLC 2 (modern)",                       "Z_CTRL", "L1"),
    "PLC3":     ("PLC 3 (legacy, no native auth)",       "Z_CTRL", "L1"),
    "SIS":      ("Safety instrumented system controller", "Z_SIS", "L1 (safety)"),
}
ENTRY_POINTS = ["ENT-WS", "VENDOR", "HMI1"]          # attacker footholds
CRITICAL = ["PLC1", "PLC2", "PLC3", "SIS"]            # protected assets
OT_HOSTS = ["HIST", "SCADA", "EWS", "HMI1", "HMI2"]   # baseline flat OT LAN
DMZ_HOSTS = ["JUMP", "HIST-DMZ"]
FIELD = ["PLC1", "PLC2", "PLC3", "SIS"]

# Edge authentication attribute (what an attacker must possess to use the edge
# after compromising its source):
#   none    - unauthenticated industrial protocol (e.g., Modbus/TCP, legacy S7)
#   host    - machine/service identity (certificate); usable by anyone who
#             controls the source host
#   pw      - single-factor credential (password)
#   mfa     - MFA + device-posture check at a PEP
#   mfa_jit - MFA + device posture + just-in-time approval (time-boxed window)
AUTH_LEVELS = ["none", "host", "pw", "mfa", "mfa_jit"]

# Attacker capability scenarios: which auth attributes the attacker can satisfy
CAPABILITIES = {
    "C0": {"none", "host"},                      # foothold, no credentials
    "C1": {"none", "host", "pw"},                # + stolen passwords
    "C2": {"none", "host", "pw", "mfa"},         # + MFA bypass / hijacked compliant session
    "C3": {"none", "host", "pw", "mfa", "mfa_jit"},  # + approved JIT window (insider) = pure topology
}
CAP_LABEL = {
    "C0": "C0: foothold only",
    "C1": "C1: + stolen passwords",
    "C2": "C2: + MFA bypass",
    "C3": "C3: + JIT approval (insider)",
}

# ---------------------------------------------------------------------------
# 2. Required (authorized) communication set R  - functional requirements
#    (source, target, purpose, ZT auth attribute, enforcement point)
# ---------------------------------------------------------------------------
REQUIRED = [
    ("ENT-WS",   "HIST-DMZ", "Business users read production reports",      "mfa",     "PEP-1 IT/DMZ"),
    ("ENT-WS",   "JUMP",     "OT engineer remote administration",           "mfa",     "PEP-1 IT/DMZ"),
    ("VENDOR",   "JUMP",     "Vendor remote maintenance (brokered)",        "mfa_jit", "PEP-0 remote-access gateway"),
    ("HIST",     "HIST-DMZ", "Historian replication (push, OT->DMZ)",       "host",    "PEP-2 DMZ/OT"),
    ("JUMP",     "EWS",      "Brokered privileged session to EWS",          "mfa_jit", "PEP-2 DMZ/OT (PAM)"),
    ("JUMP",     "SCADA",    "Brokered privileged session to SCADA",        "mfa_jit", "PEP-2 DMZ/OT (PAM)"),
    ("HMI1",     "SCADA",    "HMI client to SCADA server",                  "host",    "PEP-3 ops/supervisory"),
    ("HMI2",     "SCADA",    "HMI client to SCADA server",                  "host",    "PEP-3 ops/supervisory"),
    ("SCADA",    "HIST",     "Process data to historian",                   "host",    "PEP-3 ops zone"),
    ("SCADA",    "PLC1",     "Polling and supervisory control",             "none",    "PEP-4 control-zone allowlist (compensating)"),
    ("SCADA",    "PLC2",     "Polling and supervisory control",             "none",    "PEP-4 control-zone allowlist (compensating)"),
    ("SCADA",    "PLC3",     "Polling and supervisory control (legacy)",    "none",    "PEP-4 control-zone allowlist (compensating)"),
    ("SCADA",    "SIS",      "Read-only SIS status",                        "none",    "PEP-5 SIS conduit, read-only (compensating)"),
    ("EWS",      "PLC1",     "Logic download during approved change",       "mfa_jit", "PEP-4 change-window gate"),
    ("EWS",      "PLC2",     "Logic download during approved change",       "mfa_jit", "PEP-4 change-window gate"),
    ("EWS",      "PLC3",     "Logic download during approved change",       "mfa_jit", "PEP-4 change-window gate"),
    ("EWS",      "SIS",      "SIS programming during approved change",      "mfa_jit", "PEP-5 SIS change-window gate"),
]
R = {(s, t) for s, t, *_ in REQUIRED}
assert len(R) == len(REQUIRED) == 17, "duplicate required flow"

# Machine-to-machine service flows: in every configuration the credential is
# stored on (or bound to) the source host, so whoever controls the source can
# use the flow. They are therefore modelled as "host" in B0, B1 and ZT alike.
MACHINE_FLOWS = {("HIST", "HIST-DMZ"), ("HMI1", "SCADA"), ("HMI2", "SCADA"), ("SCADA", "HIST")}

# Baseline / zone-segmented auth (no MFA, no JIT).
def legacy_auth(s: str, t: str) -> str:
    if t in FIELD:
        return "none"
    if (s, t) in MACHINE_FLOWS:
        return "host"
    return "pw"

# ---------------------------------------------------------------------------
# 3. Configuration builders
# ---------------------------------------------------------------------------
def build_baseline() -> nx.DiGraph:
    """B0: perimeter-centric, flat OT network (typical legacy configuration)."""
    g = nx.DiGraph(name="B0 Baseline (perimeter, flat OT)")
    g.add_nodes_from(NODES)
    def add(s, t, a): g.add_edge(s, t, auth=a)
    # Broad IT->OT firewall rules (single-factor RDP/SMB/HTTP)
    for t in ["HIST-DMZ", "JUMP", "HIST", "SCADA"]:
        add("ENT-WS", t, "pw")
    # Vendor VPN terminates inside the OT LAN: reaches every OT/DMZ host
    for t in OT_HOSTS + DMZ_HOSTS:
        add("VENDOR", t, "pw")
    # DMZ and OT hosts are mutually reachable (permissive DMZ rules + flat LAN)
    hosts = OT_HOSTS + DMZ_HOSTS
    for s, t in itertools.permutations(hosts, 2):
        add(s, t, "pw")
    # Any OT host can talk the unauthenticated control protocol to any field device
    for s in OT_HOSTS:
        for t in FIELD:
            add(s, t, "none")
    for s, t in MACHINE_FLOWS:          # stored service credentials
        g.edges[s, t]["auth"] = "host"
    return g


def build_zone_segmented() -> nx.DiGraph:
    """B1: IEC 62443-style zones and conduits, no identity-aware enforcement.
    Inter-zone conduits permit only the required flows R (IP/port rules); hosts
    inside the same zone remain mutually reachable; auth stays single-factor."""
    g = nx.DiGraph(name="B1 Zone-segmented (conduits, no identity)")
    g.add_nodes_from(NODES)
    for s, t in R:
        g.add_edge(s, t, auth=legacy_auth(s, t))
    zones: dict[str, list[str]] = {}
    for n, (_, z, _) in NODES.items():
        zones.setdefault(z, []).append(n)
    for z, members in zones.items():
        for s, t in itertools.permutations(members, 2):
            # Field devices are modelled as responders only (they do not
            # initiate sessions) in every configuration.
            if s in FIELD:
                continue
            if not g.has_edge(s, t):
                g.add_edge(s, t, auth=legacy_auth(s, t))
    return g


def build_zero_trust() -> nx.DiGraph:
    """ZT: per-flow least-privilege allowlist (microsegmentation) with
    identity/context-aware PEPs; legacy field flows keep 'none' but are
    source-restricted (compensating control)."""
    g = nx.DiGraph(name="ZT Proposed Zero Trust")
    g.add_nodes_from(NODES)
    for s, t, purpose, auth, pep in REQUIRED:
        g.add_edge(s, t, auth=auth, pep=pep, purpose=purpose)
    return g


CONFIGS = {"B0": build_baseline(), "B1": build_zone_segmented(), "ZT": build_zero_trust()}
CONFIG_LABEL = {"B0": "Baseline (perimeter)", "B1": "Zone-segmented", "ZT": "Proposed Zero Trust"}

# ---------------------------------------------------------------------------
# 4. Metric functions
# ---------------------------------------------------------------------------
def subgraph_for(g: nx.DiGraph, cap: str) -> nx.DiGraph:
    allowed = CAPABILITIES[cap]
    h = nx.DiGraph()
    h.add_nodes_from(g.nodes)
    h.add_edges_from((u, v) for u, v, a in g.edges(data="auth") if a in allowed)
    return h


def reachable_pairs(g: nx.DiGraph) -> int:
    """Number of ordered pairs (s,t), s != t, with t reachable from s."""
    return sum(len(nx.descendants(g, n)) for n in g.nodes)


def entry_critical_pairs(g: nx.DiGraph) -> int:
    return sum(1 for s in ENTRY_POINTS for t in CRITICAL if nx.has_path(g, s, t))


def simple_paths(g: nx.DiGraph) -> int:
    """Count all simple directed paths from any entry point to any critical
    asset. Paths that pass THROUGH another entry point are still counted
    (an attacker may traverse a second foothold)."""
    return sum(1 for s in ENTRY_POINTS for t in CRITICAL
               for _ in nx.all_simple_paths(g, s, t))


def mean_min_hops(g: nx.DiGraph):
    d = [nx.shortest_path_length(g, s, t) for s in ENTRY_POINTS for t in CRITICAL
         if nx.has_path(g, s, t)]
    return (sum(d) / len(d)) if d else None, d


def strong_identity_coverage(g: nx.DiGraph):
    """Identity-aware coverage (IAC): share of REQUIRED flows that pass a PEP
    which evaluates an identity (MFA, MFA+JIT, or certificate-bound machine
    identity). Flows without a PEP (B0, B1) or with 'none' (legacy field
    protocols, protected only by a source allowlist) do not count."""
    strong = {"host", "mfa", "mfa_jit"}
    n = sum(1 for s, t in R if g.has_edge(s, t) and "pep" in g.edges[s, t]
            and g.edges[s, t]["auth"] in strong)
    return n, len(R)


results: dict = {}
for key, g in CONFIGS.items():
    E = set(g.edges)
    assert R <= E, f"{key} breaks a required flow"   # availability check
    unauth = E - R
    r = {
        "nodes": g.number_of_nodes(),
        "edges": len(E),
        "authorized_edges": len(E & R),
        "unauthorized_edges": len(unauth),
        "edges_unauth_list": sorted(unauth),
        "reach_pairs_C3": reachable_pairs(g),
        "possible_pairs": g.number_of_nodes() * (g.number_of_nodes() - 1),
        "field_in_degree": {t: g.in_degree(t) for t in CRITICAL},
        "unauth_cmd_sources": {t: sum(1 for u in g.predecessors(t)) for t in CRITICAL},
        "sic": strong_identity_coverage(g),
        "per_cap": {},
    }
    for cap in CAPABILITIES:
        h = subgraph_for(g, cap)
        mh, dl = mean_min_hops(h)
        r["per_cap"][cap] = {
            "entry_critical_pairs": entry_critical_pairs(h),
            "simple_paths": simple_paths(h),
            "mean_min_hops": mh,
            "reach_pairs": reachable_pairs(h),
        }
    results[key] = r


def pct_reduction(base: float, new: float) -> float:
    return (base - new) / base * 100.0

# ---------------------------------------------------------------------------
# 5. Independent validation checks (second, non-networkx computation)
# ---------------------------------------------------------------------------
def closure_by_matrix(g: nx.DiGraph, cap: str) -> int:
    """Warshall transitive closure on an adjacency matrix - independent of
    networkx traversal - used to cross-check reachable-pair counts."""
    allowed = CAPABILITIES[cap]
    ids = list(NODES)
    idx = {n: i for i, n in enumerate(ids)}
    n = len(ids)
    M = [[False] * n for _ in range(n)]
    for u, v, a in g.edges(data="auth"):
        if a in allowed:
            M[idx[u]][idx[v]] = True
    for k in range(n):
        for i in range(n):
            if M[i][k]:
                for j in range(n):
                    if M[k][j]:
                        M[i][j] = True
    return sum(M[i][j] for i in range(n) for j in range(n) if i != j)


def dfs_paths(g: nx.DiGraph, cap: str) -> int:
    """Hand-written DFS simple-path enumeration (cross-check)."""
    allowed = CAPABILITIES[cap]
    adj = {n: [v for _, v, a in g.out_edges(n, data="auth") if a in allowed] for n in g.nodes}
    total = 0
    def dfs(u, target, seen):
        nonlocal total
        if u == target:
            total += 1
            return
        for v in adj[u]:
            if v not in seen:
                seen.add(v); dfs(v, target, seen); seen.remove(v)
    for s in ENTRY_POINTS:
        for t in CRITICAL:
            dfs(s, t, {s})
    return total

checks = []
for key, g in CONFIGS.items():
    for cap in CAPABILITIES:
        a = results[key]["per_cap"][cap]["reach_pairs"]; b = closure_by_matrix(g, cap)
        checks.append((f"{key}/{cap} reach pairs nx={a} warshall={b}", a == b))
        a = results[key]["per_cap"][cap]["simple_paths"]; b = dfs_paths(g, cap)
        checks.append((f"{key}/{cap} simple paths nx={a} dfs={b}", a == b))
    r = results[key]
    checks.append((f"{key} edges = authorized + unauthorized",
                   r["edges"] == r["authorized_edges"] + r["unauthorized_edges"]))
    checks.append((f"{key} C3 reach equals full-graph reach",
                   r["reach_pairs_C3"] == r["per_cap"]["C3"]["reach_pairs"]))
# Monotonicity: more attacker capability can never reduce reachability
for key in CONFIGS:
    seq = [results[key]["per_cap"][c]["entry_critical_pairs"] for c in CAPABILITIES]
    checks.append((f"{key} monotone in capability {seq}", seq == sorted(seq)))
# ZT edge set is a subset of baseline edge set (ZT only removes / constrains)
checks.append(("ZT edges subset of B0 edges", set(CONFIGS["ZT"].edges) <= set(CONFIGS["B0"].edges)))
checks.append(("B1 edges subset of B0 edges", set(CONFIGS["B1"].edges) <= set(CONFIGS["B0"].edges)))
# Hand count of B0 edges: 4 (IT->OT) + 7 (VPN) + 7*6 (flat hosts) + 5*4 (host->field) = 73
checks.append(("B0 hand count 4+7+42+20=73", results["B0"]["edges"] == 73))

# ---------------------------------------------------------------------------
# 6. Output
# ---------------------------------------------------------------------------
def fmt(x, nd=1):
    return "n/a" if x is None else f"{x:.{nd}f}"

print("=" * 78)
print("ILLUSTRATIVE MODEL RESULTS (not measurements of a real plant)")
print("=" * 78)
for key, r in results.items():
    print(f"\n[{key}] {CONFIG_LABEL[key]}")
    print(f"  nodes={r['nodes']} edges={r['edges']} authorized={r['authorized_edges']} "
          f"unauthorized={r['unauthorized_edges']}")
    print(f"  reachable ordered pairs (topology) = {r['reach_pairs_C3']} / {r['possible_pairs']}")
    n, d = r["sic"]
    print(f"  identity-aware coverage (IAC) of R = {n}/{d} = {n/d*100:.1f}%")
    print(f"  direct sources to field assets = {r['unauth_cmd_sources']}")
    for cap, v in r["per_cap"].items():
        print(f"   {cap}: entry->critical pairs={v['entry_critical_pairs']}/12 "
              f"simple paths={v['simple_paths']} mean min hops={fmt(v['mean_min_hops'],2)} "
              f"reach pairs={v['reach_pairs']}")

b, z, s = results["B0"], results["ZT"], results["B1"]
print("\nReductions B0 -> ZT:")
print(f"  edges: ({b['edges']} - {z['edges']})/{b['edges']} = {pct_reduction(b['edges'], z['edges']):.1f}%")
print(f"  reachable pairs: ({b['reach_pairs_C3']} - {z['reach_pairs_C3']})/{b['reach_pairs_C3']} = "
      f"{pct_reduction(b['reach_pairs_C3'], z['reach_pairs_C3']):.1f}%")
pb, pz = b["per_cap"]["C3"]["simple_paths"], z["per_cap"]["C3"]["simple_paths"]
print(f"  simple attack paths (C3): ({pb} - {pz})/{pb} = {pct_reduction(pb, pz):.2f}%")
pb1, pz1 = b["per_cap"]["C1"]["simple_paths"], z["per_cap"]["C1"]["simple_paths"]
print(f"  simple attack paths (C1): ({pb1} - {pz1})/{pb1} = {pct_reduction(pb1, pz1):.2f}%")

print("\nValidation checks:")
ok = True
for name, passed in checks:
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    ok &= passed
print(f"\nALL CHECKS {'PASSED' if ok else 'FAILED'} ({sum(p for _, p in checks)}/{len(checks)})")

# --- CSV exports ----------------------------------------------------------
with open(os.path.join(DATA, "nodes.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["node_id", "description", "zone", "purdue_level", "role"])
    for n, (desc, zone, lvl) in NODES.items():
        role = "entry" if n in ENTRY_POINTS else ("critical" if n in CRITICAL else "")
        w.writerow([n, desc, zone, lvl, role])

with open(os.path.join(DATA, "edges_all_configs.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["config", "source", "target", "auth", "authorized_required_flow"])
    for key, g in CONFIGS.items():
        for u, v, a in sorted(g.edges(data="auth")):
            w.writerow([key, u, v, a, int((u, v) in R)])

with open(os.path.join(DATA, "required_flows.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["id", "source", "target", "purpose", "zt_auth", "enforcement"])
    for i, row in enumerate(REQUIRED, 1):
        w.writerow([f"R{i}", *row])

with open(os.path.join(HERE, "06_Evaluation_Data.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["config", "config_label", "capability", "capability_label", "edges",
                "unauthorized_edges", "reachable_pairs_topology", "entry_critical_pairs",
                "entry_critical_pairs_max", "simple_attack_paths", "mean_min_hops",
                "strong_identity_flows", "required_flows", "data_type"])
    for key, r in results.items():
        for cap, v in r["per_cap"].items():
            w.writerow([key, CONFIG_LABEL[key], cap, CAP_LABEL[cap], r["edges"],
                        r["unauthorized_edges"], r["reach_pairs_C3"], v["entry_critical_pairs"],
                        len(ENTRY_POINTS) * len(CRITICAL), v["simple_paths"],
                        fmt(v["mean_min_hops"], 2), r["sic"][0], r["sic"][1],
                        "illustrative-model"])

with open(os.path.join(DATA, "field_exposure.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["config", "asset", "direct_sources_in_degree", "data_type"])
    for key, r in results.items():
        for t, d in r["field_in_degree"].items():
            w.writerow([key, t, d, "illustrative-model"])

with open(os.path.join(DATA, "results.json"), "w") as f:
    json.dump({k: {kk: vv for kk, vv in v.items() if kk != "edges_unauth_list"}
               for k, v in results.items()}, f, indent=2, default=list)

# Communication matrices (row = source, col = target)
for key, g in CONFIGS.items():
    ids = list(NODES)
    with open(os.path.join(DATA, f"comm_matrix_{key}.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["src\\dst", *ids])
        for s in ids:
            w.writerow([s, *[(g.edges[s, t]["auth"] if g.has_edge(s, t) else "") for t in ids]])

sys.exit(0 if ok else 1)
