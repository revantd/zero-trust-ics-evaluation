# Zero Trust Architecture for Industrial Control Systems

## Overview

This repository contains the Python implementation used for the graph-based evaluation in the research paper *Zero Trust Architecture for Industrial Control Systems: A Security Framework for Modern Critical Infrastructure*.

The program compares three network configurations:

- **B0:** Perimeter-based security with a flat OT network.
- **B1:** Zone-based network segmentation.
- **ZT:** Proposed Zero Trust architecture with least-privilege communication rules.

## Methodology

The model represents 13 industrial network assets as a directed graph. It evaluates network reachability, entry-to-critical-asset paths, unauthorized communication edges, and identity-aware access coverage under four attacker-capability scenarios.

Independent validation checks compare graph results with matrix-based reachability calculations and a separate depth-first search.

## Requirements

- Python 3.9 or newer
- NetworkX 2.6 or newer

Install the dependency:

```bash
pip install networkx
```

## How to Run

Place `05_Calculation_Code.py` in the repository root and execute:

```bash
python 05_Calculation_Code.py
```

The program prints evaluation results and generates CSV and JSON files for further analysis.

## Important Note

All reported values are derived from an illustrative network model. They are not measurements from a real industrial control system and do not establish that an attack would succeed.

## Author

Revant Dalvi
