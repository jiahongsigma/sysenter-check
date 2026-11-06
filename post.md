# The witness that blinks: a two-day eBPF mystery that ended in an Ubuntu kernel bug

*Jiahong Dai, November 2026*

*A debugging story. The tool that came out of it is at [github.com/jiahongsigma/sysenter-check](https://github.com/jiahongsigma/sysenter-check); the bug is
[Launchpad 2170225](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2170225).*

**TL;DR.** On Ubuntu kernels 7.0.0-38 and later (24.04 HWE, 26.04, the cloud
flavours), BPF programs attached to `syscalls:sys_enter_*` tracepoints with
user-pointer arguments — `execve`, `openat`, `connect` — run on **CPU 0 only**. On
a sixteen-core machine your tracing tool sees one sixteenth of those events and
reports nothing wrong. kprobes, fentry and LSM hooks are unaffected, and so is
7.0.0-34. One command tells you whether your machine is affected: `check.sh` from
[github.com/jiahongsigma/sysenter-check](https://github.com/jiahongsigma/sysenter-check). The rest of this page is how it took me two days and one wrong
answer to get there.

## The setup

I was building a small eBPF observer: a read-only witness that records what a
sandboxed, short-lived process *actually did* — programs it ran, connections it
made, files it wrote, whether it tried to leave its cgroup — independently of
anything the process says about itself. The point is reconciliation: diff the
self-report against the kernel's account and surface every divergence.

The first build was deliberately boring. A `bpftrace` script, run as root,
attaches to a handful of tracepoints, keys everything by cgroup, and **prints**.
An ordinary-user program on the other side of a pipe parses the lines. Each
process under observation runs in its own transient systemd scope, so the probe
can tell them apart by cgroup, and cleanup can kill the whole tree.

Four of the five signals worked on the first real run and stayed reliable on
every run after:

| signal | status |
|---|---|
| attribution by cgroup | reliable |
| `exec` (programs started) | reliable |
| `connect` (network) | reliable |
| a process leaving its cgroup | reliable |
| **`open` (files written)** | **flaky — this story** |

The first run captured file writes for one of three identical sessions. Reruns
captured zero. Something was dropping write events, and the next two days went
into finding out what. The answer turned out to be a kernel bug that had been
reported a month earlier, which I only found after measuring my way to it. The
wrong turns are the useful part, so they are all here.

## The method: a lossy channel and a lossless one

The single most useful technique in the whole investigation was pairing two ways
of recording the same event:

- **`printf`** — bpftrace formats an event and ships it through a perf ring
  buffer to user space. It *can* drop under load.
- **`count()` into a map** — an in-kernel atomic increment, read once at exit. It
  does not go through the ring buffer and cannot drop events.

When the two disagree you have learned where in the pipeline the loss is. Most of
the false conclusions below came from reading only the lossy channel; most of the
real findings came from adding the lossless one.

## The falsification chain

**Hypothesis 1 — a stale bpftrace.** The distro ships 0.20. Surely a known bug.
*Falsified:* extracted and ran 0.27 (an ordeal: the "static" release is a nix
AppImage; no FUSE here; unprivileged user namespaces blocked by AppArmor; the way
through was launching the extracted binary via its own `ld-linux` with
`--library-path` over the 52 lib directories in the extracted store). Identical
zero-capture.

**Hypothesis 2 — the predicate.** The probe tested cgroup membership by walking a
kernel pointer chain to the cgroup's name. I rewrote it to gate on a map populated
at `exec`. *Falsified, and worse:* the map version captured even fewer writes. A
counting probe later showed both predicates matched **identical** event counts.
The predicate was never the variable.

**Hypothesis 3 — event loss from load.** `openat` is among the hottest syscalls;
surely our few events drown. *Falsified by the lossless counter:* it tallied only
two writes from the sessions per three-session run, not six minus losses. The events that
reached the probe genuinely were few.

**Hypothesis 4 — my launcher's sandbox.** The sessions were started through a tool
that virtualizes child I/O. *Falsified:* sandbox off, still one of three.

**Hypothesis 5 — concurrency.** Other processes on the box, my own three parallel
sessions. *Falsified:* a single isolated session captured zero.

**Hypothesis 6 — a different syscall.** `open`, `openat`, `openat2`, io_uring. I
only watched `openat`. *Tested:* all three at once. *Falsified:* zero across all
three — while the same cgroup predicate under `count()` on the same tracepoint had
just tallied 42 openats. Same probe, same predicate: `count = 42, printf = 0`.

**Hypothesis 7 — "it's printf loss then."** I wrote this down as the answer for a
while. *Falsified by going fully lossless:* a map-only run was also nearly empty.
The events were not being *matched*, not merely not printed.

**The controlled test.** Two shell writes fired directly into a scope:

```
systemd-run --user --scope --slice=test.slice -- sh -c 'echo x > /tmp/short'
systemd-run --user --scope --slice=test.slice -- sh -c 'echo x > /tmp/long; sleep 1'
```

Both files landed on disk. Both processes were provably in the slice. The
`openat` probe, lossless map included, captured **nothing** — while an earlier run
with the *same* predicate on the *same* tracepoint had matched seven opens. Same
code, same machine, different runs: sometimes it matches, sometimes it doesn't.
And the same predicate on `sched_process_exec` was reliable every single time.

That was the core, uncomfortable finding: **the capture is non-deterministic.**

## The wrong answer I lived with for two days

With a dozen root runs behind me I wrote down the most self-consistent story I
had: a **tracer-versus-kernel mismatch**. The kernel (Ubuntu 24.04's HWE line,
7.0) is newer than the bpftrace the distro ships against; `kernfs` internals had
changed between them (the parent pointer is even renamed `__parent`); a BTF walk
through a struct that moved, in the hottest context there is, could plausibly
match inconsistently — especially for microsecond-lived processes in scopes being
set up and torn down at the same time.

I also wrote down the hole in it: a wrong struct offset should fail
*consistently*, not intermittently. I called it a hypothesis, marked the signal
best-effort, and shipped the four reliable ones. That was the right call. It was
also wrong about the cause.

## The fix that did not need the answer

Independent of the mechanism, there was a cleaner design: stop watching the
syscall tracepoint and stop walking the cgroup name by hand.

- Identify the cgroup with the kernel's own helper (`bpf_get_current_cgroup_id`,
  and later `bpf_get_current_ancestor_cgroup_id` for "is this task under my base
  cgroup, and which child") — a helper, not a pointer walk.
- Capture file opens with a hook on the VFS path — `security_file_open` — via
  `fentry`, which every open reaches whatever the entry (io_uring included), and
  where `bpf_d_path` gives the whole path.

The bpftrace `kfunc` build of that design captured every write on the first run.
A libbpf/CO-RE rewrite followed and never lost an event either: 115 events in its
first live run, every one accounted for. The flaky signal was gone. The mystery
was not, and now there was a reliable reference to measure against.

## The decisive experiments

With a witness that does not blink, the question "what does the tracepoint miss"
became cheap. Four measurements, all on the same 16-core Ubuntu 24.04 machine,
kernel `7.0.0-38-generic`.

**1. Same sessions, every entry at once.** The reference hook saw 40 and 44 write-
opens per session. The `sys_enter_openat` tracepoint saw 16 and 24 calls of *any*
kind, 8 and 5 with write flags. `openat2`, `open`, `creat`, io_uring's open path:
zero. The user-space filename read at entry: never empty. So the writes were on
`openat`, and the tracepoint did not fire for most of them.

**2. System-wide, by process name.** The tracepoint against a kprobe on
`__x64_sys_openat`, for every process on the box: the box's shell got 53 of 1177;
`systemd` 0 of 515; the browser 0 of 909; a short-lived `pgrep` 12,211 of 72,700.
Every process, not just mine.

**3. One window, three readings.** bpftrace's tracepoint: 40,702. `perf stat`
reading the same tracepoint: 40,086 in 13 of the same 15 seconds. The kprobe:
49,866. bpftrace and perf agreed with each other. So not the tracer — the kernel.
(Keep this reading in mind; it was itself a clue.)

**4. Per process.** Of 566 processes that called `openat` in one window, the
tracepoint saw **every** call for 39 and **not one** call for 513. Identical `cat`
invocations went both ways. Long-lived daemons never fired at all. All or nothing,
per process — which I read, for about an hour, as a per-task flag the kernel was
failing to set. That reading was the right fact seen from the wrong side.

## The actual bug

Searching with the right words finally found it, filed a month earlier by someone
who had hit it in CI: **[Launchpad 2170225](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2170225)**,
*"linux 7.0.0-38: BPF programs on syscalls:sys_enter_* tracepoints with
user-pointer args only run on one CPU."*

Ubuntu's 7.0.0-38.38 took a stable backport of upstream `2c2b322acdcc`
("tracing: perf: Fix stale head for perf syscall tracing") without the upstream
change it depends on (`57918341dd19`, sleepable classic tracepoint programs). The
backport adds `if (hlist_empty(head)) return;` to `perf_syscall_enter()` **before**
the BPF program array is consulted. bpftrace, like every libbpf consumer, opens its
perf event on CPU 0 only. On every other CPU the list is empty, the function
returns, and the program never runs.

One more measurement, bpftrace alone, per CPU:

| cpu | `openat` calls (kprobe) | tracepoint fired |
|---|---|---|
| 0 | 585 | 585 |
| 1–15 | 19,959 in all | 0 |

Every call on CPU 0. Not one anywhere else.

Now everything resolves. "All or nothing per process" was the scheduler's view of
a per-CPU fault: a short-lived process lands on one CPU, and one time in sixteen
that CPU is 0 — 39 of 566, 6.9 %. Whole sessions missing their writes: their `sh` ran
elsewhere. `count()` and `printf` disagreeing across runs: different CPUs.
`sched_process_exec` always reliable: not a syscall tracepoint. bpftrace 0.20 and
0.27 identical: the kernel, not the tracer. And reading 3 above — the run where
the tracepoint suddenly delivered 82 % — had `perf stat -a` attached at the same
time, with a perf event on **every** CPU; the empty-list test was false
everywhere and the bug vanished while perf watched. Measuring the bug with perf
cures it for the duration of the measurement.

The `kernfs` walk was innocent. It ran fine whenever the probe ran at all.

## Who this bites

Any BPF program on a `sys_enter_*` tracepoint whose syscall takes a user-space
pointer — `execve`, `openat`, `connect`, the ones security tooling cares about —
on Ubuntu 7.0.0-38 or later (24.04 HWE, 26.04, the cloud flavours on the same
base; the same backport reached the 7.1.y stable tree), on a machine with more
than one CPU. bpftrace scripts, Inspektor Gadget, tracee-style tools, your own
libbpf programs, and CI on GitHub's `ubuntu-24.04` images since mid-October 2026
(that is where the first reports came from). It loses (N−1)/N of the events and
reports nothing wrong.

Not affected: kprobes, fentry, LSM programs, `raw_syscalls:sys_enter`,
`sys_exit_*`, `perf` itself, and 7.0.0-34 and earlier. A revert was sent to the
Ubuntu kernel team at the end of October; at the time of writing no released
kernel carries it.

## What to do

1. Run `check.sh` from [github.com/jiahongsigma/sysenter-check](https://github.com/jiahongsigma/sysenter-check): twelve seconds, a per-CPU table, a verdict.
2. If affected and you need the tracepoints: boot 7.0.0-34, or open a perf event
   for the tracepoint on every CPU (what `perf stat -a` does) so the early return
   never triggers.
3. If you can choose: hook the kernel function, not the syscall entry. A kprobe,
   an `fentry`, or an LSM hook such as `security_file_open` never passes through
   `perf_syscall_enter()`, sees io_uring, and can call `bpf_d_path`.

## Lessons

- **Pair a lossy channel with a lossless one.** `printf` next to `count()` turned
  "it's flaky" into falsifiable claims. Every wrong turn came from the lossy side.
- **Keep the hypotheses you kill.** Half of these were mine and wrong, one I had
  written down as the answer. The ruled-out list is worth more than the guess.
- **A reliable signal next to a flaky one localizes the fault.** `exec` with the
  same predicate never failing was the sharpest clue, and I under-read it: it said
  "not the predicate" and also "not a syscall tracepoint", and I only heard the
  first half.
- **Build the reference first, then measure the broken thing against it.** The
  fentry build took an afternoon and made every later experiment a ten-second
  count. Two days of probing the broken path alone got a wrong answer.
- **Your measuring instrument can cure the bug.** `perf stat -a` attached beside
  bpftrace made the tracepoint fire everywhere. If a bug disappears under
  observation, ask what the observer changed.
- **A syscall tracepoint is not evidence; a kernel function is.** On an affected
  kernel it is not even a sample.

## Appendix: the ruled-out list, in order

Not the bpftrace version. Not the predicate form. Not perf-buffer loss. Not the
map-key cap. Not the launcher sandbox. Not concurrency. Not a different
open-family syscall. Not printf loss alone. Not a BTF mismatch on the cgroup
walk. Not a per-task flag. It was an early return in
`perf_syscall_enter()`, added by a stable backport that lost its prerequisite,
delivering BPF programs on one CPU of sixteen.
