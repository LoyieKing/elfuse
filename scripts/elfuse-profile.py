#!/usr/bin/env python3
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
from collections import defaultdict

THREAD = ["guest_cpu_ns", "service_cpu_ns", "guest_wall_ns", "host_wall_ns",
          "mounts", "preempts", "wakes"]
CALL = ["calls", "attempts", "completed", "parks", "active_ns", "active_max_ns",
        "latency_ns", "latency_max_ns", "errors", "zero_returns",
        "positive_returns", "io_bytes"]


def snapshots(path):
    pending = None
    complete = []
    metadata = None
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            if not line.endswith("\n"):
                break
            row = json.loads(line)
            if row.get("v") != 1:
                raise ValueError("unsupported profile version")
            if row["type"] == "metadata":
                metadata = row
            elif row["type"] == "snapshot":
                pending = {"header": row, "metadata": metadata, "thread": {}, "syscall": {}, "pc": {}}
            elif row["type"] == "snapshot_end":
                if pending and row["seq"] == pending["header"]["seq"]:
                    pending["epoch_end"] = row["epoch"]
                    complete.append(pending)
                pending = None
            elif pending and row.get("seq") == pending["header"]["seq"]:
                kind = row["type"]
                if kind == "thread":
                    pending[kind][row["task"]] = row
                elif kind == "syscall":
                    pending[kind][(row["task"], row["nr"])] = row
                elif kind == "pc":
                    pending[kind][(row["task"], row["epoch"], row["pc"], row["lr"])] = row
    return complete


def live_wait(row, now):
    values = row["wait_ns"][:]
    # NEW=0, READY=1, RUNNING=2, BLOCKED=3, DEAD=4.
    state = row["state"]
    delta = max(0, now - row["state_start_ns"]) if row["state_start_ns"] else 0
    if state == 1:
        values[0] += delta
    elif state == 3 and 0 <= row["kind"] < len(values) - 1:
        values[row["kind"] + 1] += delta
    return values


def delta(new, old):
    return [max(0, a - b) for a, b in zip(new, old)]


def analyze(path, args):
    records = snapshots(path)
    if not records:
        raise ValueError(f"{path}: no complete snapshots")
    metadata = records[-1]["metadata"]
    if metadata is None or metadata["thread_fields"] != THREAD or metadata["syscall_fields"] != CALL:
        raise ValueError("unsupported profile field layout")
    wait_names = metadata["wait_fields"]
    for snap in records:
        for row in snap["thread"].values():
            if len(row["values"]) != len(THREAD) or len(row["wait_ns"]) != len(wait_names):
                raise ValueError("profile counter array length mismatch")
    selected = next((s for s in records if s["header"]["seq"] == args.to_seq), None) if args.to_seq else records[-1]
    if selected is None:
        raise ValueError(f"{path}: selected snapshot unavailable")
    previous = next((s for s in records if s["header"]["seq"] == args.from_seq), None) if args.from_seq else None
    if args.from_seq and previous is None:
        raise ValueError(f"{path}: baseline snapshot unavailable")
    h = selected["header"]
    before_ns = previous["header"]["mono_ns"] if previous else h["mono_ns"] - h["elapsed_ns"]
    if h["mono_ns"] < before_ns:
        raise ValueError("baseline must precede selected snapshot")
    print(f"\n{path}: host_pid={h['host_pid']} seq={previous['header']['seq'] if previous else 0}..{h['seq']} "
          f"interval_ms={(h['mono_ns'] - before_ns) / 1e6:.3f} epoch={h['epoch']}..{selected['epoch_end']}")
    print("Cumulative counters subtracted at snapshot boundaries; nontransactional concurrent reads; wall spans include host descheduling.")
    threads = []
    totals = [0] * len(THREAD)
    waits = [0] * len(wait_names)
    for key, row in selected["thread"].items():
        old = previous["thread"].get(key) if previous else None
        values = delta(row["values"], old["values"] if old else [0] * len(THREAD))
        wait = delta(live_wait(row, h["mono_ns"]), live_wait(old, before_ns) if old else [0] * len(row["wait_ns"]))
        totals = [a + b for a, b in zip(totals, values)]
        waits = [a + b for a, b in zip(waits, wait)]
        threads.append((sum(values[:2]), row, values, wait))
    print("PHASE total across task lifetimes (ms, overlapping across workers):")
    for name, value in zip(THREAD[:4], totals[:4]):
        print(f"  {name:20} {value / 1e6:12.3f}")
    for name, value in zip(wait_names, waits):
        if value:
            print(f"  wait_{name + '_ns':15} {value / 1e6:12.3f}")
    info = h["cpu_sample"]
    old_info = previous["header"]["cpu_sample"] if previous else {}
    diff = {k: max(0, v - old_info.get(k, 0)) for k, v in info.items() if k != "max_ns"}
    print("ACCOUNTING", json.dumps(diff), "lifetime_max_ns=", info["max_ns"])
    print("THREAD ranked by settled CPU: task tid generation worker cpu_ms guest_ms service_ms ready_ms blocked_ms mounts preempts wakes open_nr open_ms")
    for _, row, v, w in sorted(threads, key=lambda r: r[0], reverse=True)[:args.limit]:
        open_ms = max(0, h["mono_ns"] - row["open_start_ns"]) / 1e6 if row["open_nr"] >= 0 and row["open_start_ns"] else 0
        print(row["task"], row["tid"], row["generation"], row["worker"],
              *(f"{n / 1e6:.3f}" for n in (sum(v[:2]), v[0], v[1], w[0], sum(w[1:]))),
              *v[4:], row["open_nr"], f"{open_ms:.3f}")
    calls = defaultdict(lambda: [0] * len(CALL))
    for key, row in selected["syscall"].items():
        old = previous["syscall"].get(key) if previous else None
        v = delta(row["values"], old["values"] if old else [0] * len(CALL))
        name = (row["nr"], row["name"])
        for i, value in enumerate(v):
            if i in (5, 7):
                calls[name][i] = max(calls[name][i], row["values"][i])
            else:
                calls[name][i] += value
    print("SYSCALL ranked by active wall: nr name calls attempts completed parks active_ms latency_ms errors bytes lifetime_active_max_ms lifetime_latency_max_ms")
    for (nr, name), v in sorted(calls.items(), key=lambda r: r[1][4], reverse=True)[:args.limit]:
        print(nr, name, *v[:4], f"{v[4] / 1e6:.3f}", f"{v[6] / 1e6:.3f}", v[8], v[11], f"{v[5] / 1e6:.3f}", f"{v[7] / 1e6:.3f}")
    print("LOSS cumulative:", json.dumps({k: h[k] for k in ("task_overflow", "clock_errors")}),
          json.dumps({k: sum(r[k] for r in selected["thread"].values()) for k in ("syscall_overflow", "incomplete_calls", "pc_overflow", "pc_non_el0")}))
    print("PC owner EL0-exit samples (biased; Rosetta addresses are translated aarch64):")
    pcs = []
    for key, row in selected["pc"].items():
        old = previous["pc"].get(key) if previous else None
        hits = row["count"] - (old["count"] if old else 0)
        if hits:
            pcs.append((hits, row))
    for hits, row in sorted(pcs, key=lambda r: r[0], reverse=True)[:args.limit]:
        print("task", row["task"], "epoch", row["epoch"], hex(row["pc"]), hex(row["lr"]), "hits", hits, "rosetta", row["rosetta"])


def main():
    parser = argparse.ArgumentParser(description="Rank elfuse version-1 profile JSONL snapshots")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--from-seq", type=int, help="subtract this complete snapshot (default: process start)")
    parser.add_argument("--to-seq", type=int, help="select this complete snapshot (default: latest)")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    try:
        for path in args.files:
            analyze(path, args)
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
