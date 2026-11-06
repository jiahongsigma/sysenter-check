# sysenter-check

One command to answer: **are BPF programs on `syscalls:sys_enter_*` tracepoints
running on every CPU of this machine, or only on CPU 0?**

```
git clone https://github.com/jiahongsigma/sysenter-check && cd sysenter-check
./check.sh
```

It needs `bpftrace` and `sudo`, takes about twelve seconds, and prints a per-CPU
table and a verdict. Exit code 0 = fine, 1 = affected, 2 = could not judge.

What it looks like on an affected machine (Ubuntu 24.04, `7.0.0-38-generic`, 16 CPUs):

```
 cpu  openat calls (kprobe)  tracepoint fired
   0                   4331              4338
   1                   4460                 0
   2                   2081                 0
   ...
  15                   3397                 0

AFFECTED: of 16 busy CPUs the tracepoint fired on [0] and never on 15.
BPF programs on syscalls:sys_enter_* tracepoints are running on one CPU only on this kernel.
```

## Why this exists

Ubuntu kernels **7.0.0-38 and later** (24.04 HWE, 26.04, the `-azure`/`-aws`/`-gcp`
flavours on the same base) carry a stable backport — upstream `2c2b322acdcc`,
"tracing: perf: Fix stale head for perf syscall tracing" — without the upstream
change it depends on. The result is an early `if (hlist_empty(head)) return;` in
`perf_syscall_enter()` that runs **before** the kernel looks for BPF programs.
bpftrace, and every libbpf-based tool, open their perf event on CPU 0 only. So on
every other CPU the function returns and the BPF program never runs.

Nothing reports an error. Your tracing tool starts, attaches, and streams events —
from one CPU. On a sixteen-core machine it sees one sixteenth of `execve`, `openat`,
`connect` and the other syscalls that take a user-space pointer. Short-lived
processes are either seen whole or not at all, depending on which CPU they land on.

Tracked as [Launchpad bug 2170225](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2170225).
7.0.0-34 is unaffected. A revert has been proposed to the Ubuntu kernel team.

## Who is affected

Anything that attaches BPF to `sys_enter_*` tracepoints with user-pointer
arguments on an affected kernel and a multi-core box: bpftrace scripts, Inspektor
Gadget, tracee-style tools, your own libbpf programs, and CI jobs running them on
GitHub's `ubuntu-24.04` images since mid-October 2026.

Not affected: kprobes, fentry/fexit, LSM programs, `raw_syscalls:sys_enter`,
`sys_exit_*`, `perf stat` (it opens an event on every CPU — which also *masks*
the bug for any BPF program attached at the same time).

## What to do

- **Pick an unaffected kernel.** 7.0.0-34 or earlier until the revert ships.
- **Don't trust syscall-enter tracepoints for anything that must be complete.**
  Hook the kernel function instead (`kprobe`, `fentry`, or an LSM hook such as
  `security_file_open`); they never pass through `perf_syscall_enter()`.
- **If you must use the tracepoint**, open a perf event on every CPU for it
  (what `perf stat -a` does); the empty-list test is then false everywhere.

## How it measures

`check.bt` counts `openat()` for ten seconds two ways, per CPU: a kprobe on
`__x64_sys_openat` (ground truth — fires for every call) and the
`syscalls:sys_enter_openat` tracepoint. `check.sh` runs a small workload that
opens files from many short-lived processes so every CPU sees calls, then prints
the table. A CPU with calls and no tracepoint hits is the signature.

The write-up of how this was found — including the wrong hypothesis that held for
two days — is in [the accompanying post](post.md).
