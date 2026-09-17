"""Smoke test for parsers — loads one scenario and prints event-type counts."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # repo root (defense_agent/tests → repo)
sys.path.insert(0, str(ROOT))

from defense_agent.parsers import load_scenario  # noqa: E402


def main(scenario: str = "2018-09-20-apt-c-01") -> None:
    sd = ROOT / "output" / scenario
    name, events = load_scenario(sd)
    print(f"=== {name}: {len(events)} canonical events ===")
    by_source = Counter(e.source for e in events)
    by_type = Counter(e.event_type for e in events)
    print("by source:", by_source)
    print("by type (top 20):", by_type.most_common(20))
    if events:
        first = events[0]
        print("first event:", first)


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "2018-09-20-apt-c-01"
    main(scenario)