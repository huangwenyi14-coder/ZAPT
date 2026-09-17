"""Smoke test for detector — runs rules on a scenario and prints summary."""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.detectors import detect_scenario  # noqa: E402
from defense_agent.parsers import load_scenario  # noqa: E402


def main(scenario: str = "2018-09-20-apt-c-01") -> None:
    sd = ROOT / "output" / scenario
    t0 = time.time()
    name, events = load_scenario(sd)
    t1 = time.time()
    result = detect_scenario(events)
    t2 = time.time()
    print(f"=== {name}: parse {t1 - t0:.1f}s, detect {t2 - t1:.1f}s ===")
    print(json.dumps(result["stats"], indent=2))
    cs = result["cross_summary"]
    print(f"cross: {len(cs['beacons'])} beacons, {len(cs['lateral_movement'])} lateral, {len(cs['credential_dumping'])} cred_dumping")
    print("top beacons:")
    for b in cs["beacons"][:5]:
        print(" ", b)


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "2018-09-20-apt-c-01"
    main(scenario)