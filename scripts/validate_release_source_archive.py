#!/usr/bin/env python3
"""Validate a decrypted release archive without disclosing private diagnostics."""

from __future__ import annotations

import argparse
import pathlib
import sys

if __package__:
    from .reconstruct_release import ReconstructionError, _read_release_sources
else:
    from reconstruct_release import ReconstructionError, _read_release_sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plaintext-tar", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        _read_release_sources(args.plaintext_tar)
    except (OSError, UnicodeError, ReconstructionError, ValueError):
        print("release source validation failed closed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
