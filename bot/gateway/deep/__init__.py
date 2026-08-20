"""심층 조사 모드 — 조사 → 가설 → 검증.

설계와 문헌 근거는 private/docs/deep_mode_design.md, 배선은 bot/GATEWAY_GUIDE.md §36.
"""

from . import (baseline, condense, hypothesis, memory,  # noqa: F401
               graph, probe, run, state, verify)
