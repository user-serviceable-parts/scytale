# Benchmarking

The benchmark measures everything the library implements: the
throughput of each primitive that runs over a buffer, in the manner
of `openssl speed`, and the cost of each operation that has no
throughput to measure. It is an ordinary cargo bench target, so it
runs wherever cargo does, and one script on top of it settles a
Linux machine for the runs whose figures are published.

## Running it

```sh
cargo bench -p scytale                       # everything
cargo bench -p scytale -- aes-256-gcm        # one algorithm, every kernel
cargo bench -p scytale -- aes-256-gcm default  # what this machine runs
cargo bench -p scytale -- gcm none           # rows matching both words
cargo bench -p scytale -- sha,blake2         # either word
cargo bench -p scytale -- sig                # a whole group
cargo bench -p scytale -- --seconds 0.25     # a quicker sweep
cargo bench -p scytale -- --help
```

A full sweep at the default second for each figure takes about half
an hour. From the published crate the commands are the same,
without `-p scytale`, run in the crate's directory.

A filter is a bare word. A row runs when its group, its name and the
features that select its kernel together contain every word given;
commas inside a word offer alternatives, so `none ctr,ecb-enc` keeps
both of those rows, measured in the one run and so comparable. The
word `default` picks the kernel the library chooses on this machine,
so `aes-256-gcm default` is what a caller here gets and nothing else.

| Option | What it does |
| --- | --- |
| `--seconds N` | CPU time to spend on each figure; the default is 1 |
| `--json PATH` | also write every figure, with its spread, as JSON |
| `--compare OLD NEW` | compare two such documents instead of measuring |
| `--self-test` | check the harness instead of measuring |
| `--help` | the usage |

Cargo runs a bench target from the crate's directory, so a relative
`--json` path is relative to `scytale/`. Give an absolute one.

`cargo test --benches`, or `--all-targets`, builds the benchmark and
runs only its self-test: a test run never starts a sweep.

## What a figure is

A primitive that runs over a buffer is reported at six sizes, from
one block to sixteen kilobytes: the small end shows what a call
costs before any data moves, the large end the steady state, and the
distance between them is what says whether a faster bulk path would
need a short-message fallback beside it. A primitive whose cost is
the call rather than the data, which is every key operation, both
key derivations and the two format-preserving modes, is reported
instead as operations a second and the time one takes.

Every figure comes in two units.

- **Cycles a byte**, or cycles an operation, is what the code costs.
  It barely moves between runs, between a fast core and a slow one,
  or as a laptop warms up and its clock falls, so it is the figure
  to compare across commits.
- **Megabytes a second**, or operations a second, is what a caller
  feels on this machine as it stood.

The two are read around the same work, so the JSON also records the
clock rate each cell saw.

A figure is the median of thirty-one samples, not a mean over one
long run, since an interrupt, a migration, or a neighbour on the
other thread of the core only ever slows a sample and never speeds
one. The spread of the middle half of the samples is kept with each
figure, and a figure whose spread passes five percent of its median
is marked `*` in the table: the number is still the best there is,
but the run was not quiet. Within a section the cells are sampled in
rounds, one sample of every cell and then the next, so that a clock
drifting over the minutes lands on every row of the section alike.

### How the report is laid out

The benchmark measures a feature profile at a time and says so on
standard error as it goes. The report is written once, at the end,
on standard output, and is arranged for looking an algorithm up.

```text
aead
                              16       64      256     1024     8192    16384
  aes-256-gcm-enc
    aes+ssse3+avx+avx2+vaes+pclmulqdq+vpclmulqdq
                       cpb   20.54     5.51     1.74     0.62     0.42     0.39
                      MB/s   106.8    397.7   1259.5   3530.6   5170.3   5621.5
    aes+ssse3+avx+pclmulqdq
                       cpb   20.45     5.51     1.74     0.89     0.67     0.65
                      MB/s   107.2    397.7   1257.1   2458.9   3283.8   3398.1
    none
                       cpb  264.00    98.05    71.53    64.94    63.02    62.91
                      MB/s     8.3     22.4     30.7     33.8     34.8     34.9
  aes-256-gcm-dec
    ...
```

- **Groups** are the library's modules, in this order: `aead`,
  `cipher`, `hash`, `kdf`, `kem`, `kex`, `mac`, `pke`, `random`,
  `sig`.
- **Algorithms** are in alphabetical order within a group, with a
  run of digits read as the number it is, so `ml-kem-512` comes
  before `ml-kem-1024`. The operations of one algorithm are in the
  order they are done: `enc` before `dec`, `wrap` before `unwrap`,
  `keygen`, `sign`, `verify`.
- **Kernels** are listed under an algorithm, every one this
  processor can run. The first is the one the library picks on this
  machine, which is what a caller gets. The rest follow in the
  library's own order of preference, down to `none`, which is the
  portable code.

A kernel is named by the features that select it: the least set a
processor must have for the library to choose that code. So
`aes+ssse3+avx+pclmulqdq` is what a processor with those and no
VAES would run. `isolated` is not a processor feature but a promise
by the program that nothing untrusted shares its caches, which
admits the table-driven AES.

An algorithm with one kernel is its name and its figures on the same
lines, with nothing to list. The operations, which are measured
under the reported set alone, are always so.

Everything is built from the public types, and what chooses the code
under them is the feature set in force, as it is for any caller. A
row is measured again under another profile only when that profile
moves it onto code not measured yet, so nothing is measured twice
and every combination a caller can reach is measured once.

## Off Linux

The cycle counter is the Linux kernel's, through `perf_event_open`.
On any other system the benchmark runs the same and reports the
rates alone. On Linux in a virtual machine, or with
`kernel.perf_event_paranoid` above 2, the counter cannot be opened
and the same happens.

Nothing in the benchmark pins it to a core. Unpinned, a row records
which core the scheduler picked as much as how fast the code is,
which matters most on a hybrid processor; pin it with whatever the
system offers, `taskset -c 0` on Linux. There is no benchmark on
wasm, which has no thread clock to read.

## Comparing two runs

```sh
cargo bench -p scytale -- gcm --json /tmp/before.json
# ... change something ...
cargo bench -p scytale -- gcm --json /tmp/after.json
cargo bench -p scytale -- --compare /tmp/before.json /tmp/after.json
```

The comparison sets the two documents side by side, row by row and
kernel by kernel, in cycles where both have them. A figure counts as
changed only when it moved by more than both spreads together, and
the command fails when any figure is worse by that much, so a check
before a push has a yes or a no.

A document written before the rows carried their group and kernel
cannot be matched against one written since, and is refused with a
message saying so; measure again.

## Official runs: `scripts/bench`

The figures that are published, in `scytale/benchmarks/`, come from
a machine that has been settled first, so that the rates repeat
between runs as well as the cycle counts do. `scripts/bench` does
the settling, the run and the putting back. It is for Linux only and
needs root, through `sudo` from your own account:

```sh
sudo scripts/bench --save i7-1355u     # the pass that is published
sudo scripts/bench aegis --seconds 3   # some rows, on a settled core
sudo scripts/bench --restore           # put back a run that was cut off
```

| Option | What it does |
| --- | --- |
| `--cpu N` | the CPU to settle and pin to |
| `--save NAME` | keep `scytale/benchmarks/NAME.md` and `NAME.json` |
| `--restore` | put the machine back, and nothing else |

Everything else on the command line goes to the benchmark.

With no `--cpu`, the CPU is the one with the highest clock, and the
lowest numbered among equals, so a hybrid processor is measured on a
performance core.

### What it changes

Each step is taken only where the kernel offers the file, and each
value is written to `target/bench.state` before it is changed, which
is what is put back.

| Change | Why |
| --- | --- |
| Turbo off | the clock is the base clock, not whatever thermal headroom the last minute left |
| The CPU's minimum clock raised to its maximum | the governor has no range left to move in |
| The other thread of the core taken offline | nothing shares the core's units with the run |
| Interrupts moved to the other CPUs | none lands in the middle of a sample |
| `kernel.perf_event_paranoid` lowered to 2 | the cycle counter opens for an unprivileged run |

A settled machine is not the machine as it is normally used; it is
the same machine every time, which is the point.

Only the settling is done as root. The build is done first, before
anything is changed, and the build and the measuring both run as the
user who called `sudo`, pinned to the settled CPU, so what they leave
in `target/` and `scytale/benchmarks/` is that user's.

The machine is put back when the script ends, however it ends: at
the end of the run, on a failure, on an interrupt. A run cut off
with no chance to do that, by a power failure, say, leaves the state
file behind, and `sudo scripts/bench --restore` puts the machine
back from it. The script refuses to start while that file exists.

### What `--save` keeps

- `NAME.json`: every figure with its spread, the clock, the sample
  count and what the machine said about itself. It is what
  `--compare` reads.
- `NAME.md`: the report as it was printed, under a header saying
  which commit it measured and what the machine was doing: the
  processor, the CPU it was pinned to, the other thread of the core,
  the governor, turbo, the energy preference, mains or battery, the
  load, how often the core was throttled during the run, the kernel
  and the toolchain.

Rerunning replaces both, which is why the header is there. A release
runs it on the reference machine; `RELEASING.md` says when.

## Reading the numbers

Counter mode and GMAC are the two halves of GCM measured apart: the
keystream without the hash, and the hash without the keystream. If
the reciprocal of the GCM rate is close to the sum of their
reciprocals, the two halves are running one after the other and a
single loop that interleaved them would have the whole of that
difference to win. If GCM already beats that sum, the processor is
overlapping them on its own.

Key wrapping is six passes over its input by construction, so it
reads an order of magnitude below the mode rows above it. CFB1 is a
block operation per bit, and reads as such.

ML-DSA signing repeats until a candidate passes, so its cost depends
on the message and not only on the parameter set; a stronger set is
not reliably slower. Both key generation figures for RSA and the
signature figures for SLH-DSA vary for the same kind of reason.

A laptop measured on battery reports about half the rates, evenly
across every row, and nearly the same cycles a byte: that is the
clock and not the code, and the recorded clock rate says so.

GCM-SIV, XPN and CCM have no form that takes a message in pieces, so
their decryption rows are the one call with a tag that does not
match. All three do the whole of the work before they look at the
tag, so the figure is the decryption, with the wipe of the refused
buffer on top. Unwrapping is measured the same way, on input that is
not a wrapped key: the six passes are made before the check value is
looked at.

AEGIS and the other constructions with a fixed cost for each message
read very differently at the two ends of the table. The sixteen-byte
column is nearly all that fixed cost, and the sixteen-kilobyte
column nearly none of it.
