#!/usr/bin/env python3
"""Fail when a C source file carries non-ASCII outside the diagram set.

The convention is ASCII prose. The tree needs one carve-out: the flow diagrams
several headers carry are worth more than the rule they break, and they need
the Box Drawing block to be readable at all. Everything else outside ASCII
fails, which is the half that had no enforcement before: an em dash, a smart
quote, an ellipsis, a non-breaking space, an arrow, a zero-width joiner.

Scope is the C family under src, tests and frama-c-stubs. Shell is left out on
purpose: scripts/test-git-hooks.sh carries an em dash as the fixture that proves
the commit-message hook rejects one, so a gate over .sh would fail on a file
whose whole job is to contain the character.

Python rather than grep: BSD grep has no -P, so the codepoint escapes the
convention documents match nothing on a stock macOS runner and report a clean
tree.
"""

import argparse
import subprocess
import pathlib
import sys
import unicodedata

# U+2500-U+257F  Box Drawing
# U+25B4 U+25B8 U+25BE U+25C2  small triangle arrowheads, for diagram edges
ALLOWED = set(range(0x2500, 0x2580)) | {0x25B4, 0x25B8, 0x25BE, 0x25C2}

ROOTS = ("src", "tests", "frama-c-stubs")
SUFFIXES = (".c", ".h", ".S")


def source_files():
    """Every source under ROOTS, tracked or merely added but not ignored.

    --others --exclude-standard is what check-commentflow.sh uses, and for the
    same reason: a new file is untracked for as long as it takes to write it,
    and a style gate that skips it locally only speaks up once the mistake is
    already committed.
    """
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
         "--", *ROOTS],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return sorted({p for p in out.split("\0")
                   if p.endswith(SUFFIXES) and pathlib.Path(p).is_file()})


def offenders(text):
    """Yield (line, column, codepoint, name) for each disallowed character.

    Split on newline rather than with splitlines(), which also breaks on
    U+0085, U+2028 and U+2029 and would consume the very characters this is
    looking for, reporting the file clean.
    """
    for lineno, line in enumerate(text.split("\n"), 1):
        for col, ch in enumerate(line, 1):
            cp = ord(ch)
            if cp > 0x7F and cp not in ALLOWED:
                yield lineno, col, cp, unicodedata.name(ch, "unnamed")


def check(paths):
    bad = 0
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            print(f"{path}: not valid UTF-8")
            bad += 1
            continue

        # The overwhelming majority of files are pure ASCII, and this turns the
        # scan into one C-level pass instead of a Python loop per character.
        if text.isascii():
            continue

        for lineno, col, cp, name in offenders(text):
            # Reported by codepoint and name: several of the characters this
            # exists to catch are invisible in a terminal.
            print(f"{path}:{lineno}:{col}: U+{cp:04X} {name}")
            bad += 1
    return bad


def self_test():
    """The gate has to fail on the characters it exists to catch."""
    cases = [
        ("em dash", "a — b", True),
        ("smart quote", "“q”", True),
        ("ellipsis", "a…", True),
        ("non-breaking space", "a b", True),
        ("rightwards arrow", "a → b", True),
        ("zero-width joiner", "a\u200db", True),
        ("line separator", "a\u2028b", True),
        ("paragraph separator", "a\u2029b", True),
        ("next line", "a\u0085b", True),
        ("box drawing", "┌─┐", False),
        ("triangle arrowhead", "▾", False),
        ("plain ascii", "a -> b", False),
    ]
    failures = 0
    for label, text, want_flagged in cases:
        got = bool(list(offenders(text)))
        if got != want_flagged:
            print(f"self-test: {label}: expected flagged={want_flagged}, got {got}")
            failures += 1
    if failures:
        return 1
    print("check-ascii self-test passed")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--self-test", action="store_true", help="check the gate against known cases"
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    paths = source_files()
    bad = check(paths)
    if bad:
        print(f"\n{bad} non-ASCII character(s) outside the diagram set")
        return 1
    print(f"character set clean across {len(paths)} source file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
