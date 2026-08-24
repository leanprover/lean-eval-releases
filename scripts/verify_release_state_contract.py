#!/usr/bin/env python3
"""Verify the reviewed production State code contract before executing it."""

from __future__ import annotations

import argparse
import pathlib
import sys

from release_orchestrator import (
    STATE_RELEASE_CONTRACT_COMMIT,
    STATE_RELEASE_CONTRACT_TREES,
)
from release_qualification import QualificationError, qualify_repository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        qualify_repository(
            args.state_root,
            "leanprover/lean-eval-state",
            STATE_RELEASE_CONTRACT_COMMIT,
            STATE_RELEASE_CONTRACT_TREES,
        )
    except (QualificationError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
