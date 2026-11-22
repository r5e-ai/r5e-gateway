# Encrypted spool: measured cost (2026-11-14)

Produced by `spool_bench_test.exs` (`MIX_ENV=test mix test --include perf
apps/recurse_gateway/test/recurse_gateway/provenance/spool_bench_test.exs`),
three consecutive runs on top of `8246a0f7`, on the machine below. Files go to
an ExUnit `tmp_dir` on the local APFS SSD; neither path fsyncs a spool file
(the old plain spool did not either), so these are page-cache numbers: the cost
of AES-256-GCM + framing, not of the disk.

Machine: Apple M5 Pro, 24 GiB, 18 schedulers, OTP 28, Elixir 1.19.5,
OpenSSL 3.1.6 (`:crypto`). Workload: random bytes appended to
`PayloadCapture` exactly as the proxy does; "plain" is the old spool
(`:delayed_write` file in `$TMPDIR/r5e-capture`), "sealed" is the R5ES1 spool
under a `SpoolKeys` epoch with `Runtime` reporting `spool?: true`.

## Time added inside `PayloadCapture.append/2`, per 4 KiB chunk (350 KB body, 200 bodies per run)

| run | plain p50 | plain p99 | sealed p50 | sealed p99 |
|---|---|---|---|---|
| 1 | 0.13 µs | 30.8 µs | 2.21 µs | 35.0 µs |
| 2 | 0.13 µs | 23.9 µs | 2.25 µs | 46.7 µs |
| 3 | 0.13 µs | 14.9 µs | 2.21 µs | 32.8 µs |

Whole 350 KB body (all appends + `result/1`):

| run | plain p50 | plain p99 | sealed p50 | sealed p99 |
|---|---|---|---|---|
| 1 | 115.2 µs | 1 193.5 µs | 382.9 µs | 1 029.9 µs |
| 2 | 154.1 µs | 384.8 µs | 427.7 µs | 734.7 µs |
| 3 | 98.5 µs | 498.6 µs | 374.5 µs | 592.1 µs |

**Added per 350 KB streamed body: ≈ 0.27–0.28 ms at p50, ≈ 0.1–0.35 ms at
p99**, against a model call that takes seconds. The sealed path holds at most
one 64 KiB chunk per direction in memory. A 64 KiB chunk is sealed when the
65 537th byte arrives, so most 4 KiB appends only buffer (p50 ≈ 2.2 µs) and one
in sixteen seals 64 KiB (the p99).

## Throughput, one 100 MB body, 16 KiB appends

| run | plain | sealed | sealed per-append p50 / p99 |
|---|---|---|---|
| 1 | 1 905.9 MB/s | 1 163.8 MB/s | 6.50 µs / 42.0 µs |
| 2 | 3 437.1 MB/s | 976.8 MB/s | 6.46 µs / 91.0 µs |
| 3 | 3 918.0 MB/s | 1 161.9 MB/s | 7.58 µs / 41.3 µs |

Ship side (off the request path): reading a 100 MB sealed file back through
the store reader (decrypt + SHA-256 check against the reference) runs at
≈ 1 200.6–1 258.8 MB/s (79.4–83.3 ms).

## 16 concurrent streams × 10 MB, 4 KiB appends (aggregate)

| run | plain | sealed | plain p50 / p99 per append | sealed p50 / p99 per append |
|---|---|---|---|---|
| 1 | 3 152.6 MB/s | 3 418.8 MB/s | 0.13 / 309.5 µs | 2.96 / 232.3 µs |
| 2 | 3 117.8 MB/s | 3 719.8 MB/s | 0.13 / 300.2 µs | 2.96 / 221.0 µs |
| 3 | 4 425.4 MB/s | 3 678.8 MB/s | 0.13 / 243.0 µs | 3.00 / 260.7 µs |

Under concurrency the p99 of both paths is dominated by scheduling and file
I/O, not by the cipher; aggregate sealed throughput is ≈ 3.4–3.7 GB/s.

## Not measured here

- fsync cost (neither path syncs spool files; the log syncs the records).
- Adoption: with the hash taken while streaming, adopting a sealed spool file
  into the content directory is a single `rename(2)` plus `touch`.
