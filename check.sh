#!/bin/bash
# sysenter-check — are BPF programs on syscalls:sys_enter_* tracepoints running
# on every CPU of this machine, or only on CPU 0?
#
# Needs: bpftrace, root (sudo). Takes ~12 s. Output: a per-CPU table and a verdict.
#
# Background: Ubuntu kernels 7.0.0-38 and later (24.04 HWE, 26.04, the cloud
# flavours) carry a stable backport that makes perf_syscall_enter() return
# before running BPF programs on any CPU without a perf event; bpftrace and
# every libbpf consumer open their event on CPU 0 only, so programs on
# sys_enter_* tracepoints with user-pointer arguments (execve, openat, ...)
# run on CPU 0 alone. Nothing reports an error. Launchpad bug 2170225.
set -u
here=$(cd "$(dirname "$0")" && pwd)
command -v bpftrace >/dev/null || { echo "bpftrace is needed"; exit 2; }
out=$(mktemp)
sudo bpftrace -B none -o "$out" "$here/check.bt" &
probe=$!
# a workload that opens files from many processes, spread over the CPUs
end=$((SECONDS + 9))
while [ $SECONDS -lt $end ]; do
  pids=""
  for i in 1 2 3 4; do cat /etc/hostname /etc/os-release >/dev/null 2>&1 & pids="$pids $!"; done
  wait $pids   # only this round's children, never the probe
  ls /proc >/dev/null 2>&1
done
wait $probe
python3 - "$out" "$(nproc)" <<'PY'
import re, sys
out, ncpu = sys.argv[1], int(sys.argv[2])
kp, tp = {}, {}
for line in open(out):
    m = re.match(r"@(kprobe|tracepoint)\[(\d+)\]: (\d+)", line.strip())
    if m:
        (kp if m.group(1) == "kprobe" else tp)[int(m.group(2))] = int(m.group(3))
print(f"{'cpu':>4} {'openat calls (kprobe)':>22} {'tracepoint fired':>17}")
for c in sorted(kp):
    print(f"{c:>4} {kp[c]:>22} {tp.get(c, 0):>17}")
busy = [c for c in kp if kp[c] >= 10]
silent = [c for c in busy if tp.get(c, 0) == 0]
if len(busy) < 2:
    print("\nNot enough CPUs saw calls to judge; run again (or on a less idle machine).")
    sys.exit(2)
if not silent:
    print(f"\nOK: the syscall-enter tracepoint fired on all {len(busy)} busy CPUs. Your kernel is not affected.")
    sys.exit(0)
fired = sorted(set(busy) - set(silent))
print(f"\nAFFECTED: of {len(busy)} busy CPUs the tracepoint fired on {fired or 'none of them'} and never on {len(silent)}.")
print("BPF programs on syscalls:sys_enter_* tracepoints are running on one CPU only on this kernel.")
print("See https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2170225 — kprobe/fentry/LSM hooks are unaffected.")
sys.exit(1)
PY
rc=$?; rm -f "$out"; exit $rc
