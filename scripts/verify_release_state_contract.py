#!/usr/bin/env python3
"""Verify one reviewed State code contract before executing checked-out code."""

from __future__ import annotations

import argparse
import pathlib
import sys

from release_orchestrator import (
    STAGING_STATE_RELEASE_CONTRACT_COMMIT,
    STAGING_STATE_RELEASE_CONTRACT_TREES,
    STATE_RELEASE_CONTRACT_COMMIT,
    STATE_RELEASE_CONTRACT_TREES,
)
from release_qualification import QualificationError, qualify_repository

STATE_CONTRACTS = {
    "production": (
        "leanprover/lean-eval-state",
        STATE_RELEASE_CONTRACT_COMMIT,
        STATE_RELEASE_CONTRACT_TREES,
    ),
    "staging": (
        "leanprover/lean-eval-state-staging",
        STAGING_STATE_RELEASE_CONTRACT_COMMIT,
        STAGING_STATE_RELEASE_CONTRACT_TREES,
    ),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True, type=pathlib.Path)
    parser.add_argument(
        "--environment",
        choices=sorted(STATE_CONTRACTS),
        required=True,
    )
    args = parser.parse_args(argv)
    repository, contract_commit, contract_trees = STATE_CONTRACTS[args.environment]
    try:
        qualify_repository(
            args.state_root,
            repository,
            contract_commit,
            contract_trees,
            reject_untracked=True,
        )
    except (QualificationError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
