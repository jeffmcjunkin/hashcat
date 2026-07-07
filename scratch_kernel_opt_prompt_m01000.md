# Optimization task: hashcat `-m 1000` (NTLM) kernels on RTX 3090

You are a GPU kernel-optimization engineer working in the hashcat repository at
`C:\Users\jeff\Documents\hashcat` on a Windows 11 host. Your job is to **measurably
speed up the `-m 1000` (NTLM = MD4(UTF-16LE(password))) cracking kernels on this
machine's NVIDIA RTX 3090, without regressing correctness or other hash modes.**

Treat this as a rigorous, measurement-driven engineering task, not a rewrite. `-m 1000`
is already one of the most heavily hand-optimized kernels in hashcat; assume gains are
small and hard-won, and that your first duty is to find out *whether we are already at the
hardware roofline* before changing anything. A change that is not backed by a stable,
repeated benchmark delta does not land.

---

## 1. Hardware & environment (verified)

- GPU: **NVIDIA GeForce RTX 3090**, GA102, **sm_86**, 82 SMs, 24 GB, driver 610.62.
  - Ampere GA10x SM: 4 warp schedulers; **INT32 throughput is 64 ops/SM/clock** (half of
    FP32's 128) — MD4 is *integer-bound* (adds, rotates, boolean), so INT32 issue rate,
    `IADD3`/`LOP3`/`SHF` fusion, and ILP are what matter. 65536 regs/SM, 1536 max
    resident threads/SM (48 warps). Full occupancy needs ≤ 42 regs/thread.
- CUDA Toolkit **v13.3** is installed; `nvcc`, `ptxas`, `cuobjdump`, `nvdisasm` are on PATH
  in a fresh terminal (`...\CUDA\v13.3\bin\x64`). Nsight Compute (`ncu.exe`) if present is
  the preferred profiler. A stale-PATH terminal reports "Failed to initialize NVIDIA RTC
  library" — open a new terminal or prepend the machine PATH.
- Binary: `hashcat.exe` (v7.1.2-382-g2d71af371) is already built in the repo root and runs
  natively. hashcat compiles OpenCL/CUDA kernels **at runtime via NVRTC**, so **editing a
  `.cl` file requires NO `make` rebuild** — just re-run hashcat. The compiled-kernel cache
  is keyed on source hash and auto-invalidates on edit; if in doubt, clear the kernel cache
  directory or run with a cold cache and confirm a recompile happened.
- If you need to rebuild the host binary itself (only for C-side changes, e.g. tuning
  loader or module), use WSL Ubuntu 24.04: `wsl -d Ubuntu-24.04 -- bash -lc 'cd
  /mnt/c/Users/jeff/Documents/hashcat && export PATH=$HOME/.cargo/bin:$PATH && make win
  -j"$(nproc)"'`. Pre-req gotcha: the rust windows target must be installed once
  (`rustup target add x86_64-pc-windows-gnu`) or the parallel build races. Kernel-only work
  should not need this.

## 2. Baseline (reproduce this first)

Measured baseline: **MD5 sanity `-b -m 0 -d 1` ≈ 67.8 GH/s; you must capture the `-m 1000`
number yourself.** Establish a stable baseline before touching code:

```
# fresh terminal
cd C:\Users\jeff\Documents\hashcat
.\hashcat.exe -b -m 1000 -d 1 -D 2            # -D 2 = GPU backend only; -d 1 = the 3090
```

Measurement protocol (do every time, baseline and after each change):
- Run the benchmark **≥3 times**, discard the first (warm-up / clock spin-up), report
  median of the rest. NTLM is fast enough that noise and **thermal/clock throttling**
  dominate — watch `nvidia-smi -l 1` in parallel; if the card leaves its boost clock or
  heats past ~80 °C, let it settle. Report the clock you observed alongside the H/s.
- Prefer `--machine-readable` for parsing, and pin work with `-d 1`.
- Benchmark mode exercises the `a3-optimized` single-hash path. Also validate a realistic
  run, e.g. a mask attack against a known NTLM hash, to confirm end-to-end speed matches:
  `.\hashcat.exe -m 1000 -a 3 <hash> ?a?a?a?a?a?a?a -d 1 -w 4 --status`
- Record: kernel-accel, kernel-loops, and vector-width that autotune selected (shown at
  startup / in `--status`), plus register count and occupancy from the profiler.

## 3. The code you are optimizing

Kernels (runtime-compiled, edit freely, no rebuild):
- `OpenCL/m01000_a3-optimized.cl` — **primary target** (mask/brute, benchmarked path).
  Contains `m01000m` (multi-hash) and `m01000s` (single-hash w/ reverse-MD4 early-reject).
- `OpenCL/m01000_a0-optimized.cl`, `OpenCL/m01000_a1-optimized.cl` — dict+rules, combinator.
- `OpenCL/m01000_a{0,1,3}-pure.cl` — length-agnostic fallbacks (pw > 27).

Shared primitives (⚠ **touching these affects many hash modes — see guardrails**):
- `OpenCL/inc_hash_md4.h` — `MD4_F/G/H`, `MD4_Fo/Go` (`bitselect`→LOP3), `MD4_STEP/STEP0/STEP_S`
  (`hc_add3`→IADD3, `hc_rotl32`→SHF).
- `OpenCL/inc_platform.cl` — `hc_rotl32`, `hc_funnelshift_*` (inline PTX `shf.l.wrap.b32`).
- `OpenCL/inc_common.cl/.h`, `OpenCL/inc_simd.h` (`u32x`, `VECT_SIZE`, `COMPARE_*_SIMD`,
  `MATCHES_NONE_VV`), `OpenCL/inc_vendor.h` (`IS_NV`, `USE_BITSELECT`, `USE_FUNNELSHIFT`).

Host-side (C, needs `make win` if changed):
- `src/modules/module_01000.c` — `OPTI_TYPE`/`OPTS_TYPE`, kernel_accel/loops min/max
  (currently `MODULE_DEFAULT` = autotuned), `pw_max`.
- `tunings/Modules_default.hctune` — NTLM/nvidia row is `ALIAS_nv_real_simd 3 1000 4 A A`
  (attack 3, vector-width **4**, accel/loops autotune). `tunings/Alias.hctune` maps device
  names → `ALIAS_nv_real_simd`. Format documented in `tunings/README.md`. Tuning-DB edits
  do **not** need a rebuild (loaded at startup).

Current optimizations already in place (do **not** "discover" these as if new; build on them):
- Round constants `w[i]+MD4C0x` precomputed outside the inner loop.
- `m01000s` reverse-MD4 meet-in-the-middle: peels final steps backward from the target
  digest, early-rejects mid-round via `if (MATCHES_NONE_VV(...)) continue;`.
- `MD4_STEP0` drops the message-word add where the word is known-zero (NTLM zero-padding).
- Base+mask fold: `w0 = w0l | w0r` with `words_buf_r` — the fastest-varying position costs
  no extra add.
- SIMD `u32x` at VECT_SIZE 4; `bitselect`/`hc_add3`/funnel-shift instruction selection.

## 4. Method (one change at a time)

1. **Profile the baseline.** Use `ncu` (Nsight Compute) on a live short run, or extract the
   SASS. Determine the binding constraint: is the kernel compute-bound on the INT32 pipe,
   occupancy-limited by registers, or launch/tail-limited? Capture: achieved occupancy,
   registers/thread, warp stall reasons, IPC, and the instruction mix (count of
   `IADD3`/`LOP3`/`SHF`/`IMAD` in the hot loop). To read SASS, dump the kernel: run hashcat
   once to populate the cache, or compile the `.cl` standalone through NVRTC/nvcc for
   `-arch=sm_86` and `cuobjdump -sass` / `nvdisasm`.
2. **Form a specific hypothesis** tied to the measured bottleneck. Candidate levers, roughly
   in order of expected value:
   - **Tuning DB**: sweep vector-width (1/2/4/8) and fixed kernel-accel/loops for this exact
     device; autotune's pick is not always optimal. Cheapest experiment, no code change.
   - **Occupancy vs ILP**: measure register count; test whether reducing registers (or
     `FIXED_LOCAL_SIZE`/`-T`) raises occupancy enough to help, or whether the kernel is
     already correctly trading occupancy for ILP.
   - **Instruction selection / SASS**: verify the F/G/H boolean actually lowers to a single
     `LOP3.LUT` per step and rotates to a single `SHF`; check `ptxas` isn't materializing
     redundant `MOV`/`IMAD`. Look for steps that could fuse another add into `IADD3`.
   - **Early-reject depth** in `m01000s`: can another state word be reversed to reject one
     step sooner, or the `MATCHES_NONE` checks be reordered for earlier exit?
   - **Loop/unroll structure**, `words_buf_r` access, and whether `a0`/`a1` (less optimized
     than `a3`) have larger headroom for their own workloads.
3. **Implement the smallest change**, re-run the full measurement protocol, and **keep only
   if the median improves beyond noise** (state the noise band). Revert otherwise. Log every
   experiment: hypothesis → change → before/after H/s + clocks + occupancy → verdict.

## 5. Correctness gates (mandatory before claiming any win)

- hashcat runs a **self-test** for the mode on startup; it must pass. Additionally crack a
  **known NTLM hash** and confirm the recovered plaintext, in **every** attack mode you
  touched: `-a 3` (mask), `-a 0` (wordlist+rule), `-a 1` (combinator), and both the
  optimized and pure kernels (force pure with a > 27-char candidate; force optimized with
  short ones).
- Example known vector: NTLM("password") = `8846f7eaee8fb117ad06bdd830b7586c`.
  `echo 8846f7eaee8fb117ad06bdd830b7586c > t.hash; .\hashcat.exe -m 1000 -a 3 t.hash password`
  must recover it. Use several lengths (crossing the 27-char optimized/pure boundary) and a
  multi-hash file (exercises `m01000m` + bitmap path, not just `m01000s`).
- If you modified a **shared** header (`inc_hash_md4.*`, `inc_platform.*`, `inc_common.*`,
  `inc_simd.*`), you have potentially changed MD4/MD5/NTLM-family and every mode using those
  helpers. Re-run self-tests for a representative set (e.g. `-m 0, 100, 1000, 2500`-adjacent
  fast modes) and note that the same `.cl` is also compiled to native CPU (`emu_*`) — do not
  break the non-NVIDIA path.

## 6. Guardrails

- **Prefer edits scoped to `m01000_*.cl`** over shared headers. A 1% NTLM gain that risks
  20 other modes is not worth it unless separately proven safe.
- Keep all backends compiling: the same source feeds CUDA (NVRTC), HIP, OpenCL, Metal, and
  native CPU emu. Don't add sm_86-only inline PTX without guarding it (`#if defined IS_CUDA`
  / `HAS_SHFW`-style feature macros) and a portable fallback.
- Don't hand-hack values into autotune that only hold at one thermal state; tuning-DB entries
  should be robust across a warmed-up card.
- Do not commit. Leave the working tree with your changes, and hand back a report.

## 7. Deliverable

A concise report containing:
1. Baseline vs final `-m 1000` numbers (median H/s + observed clocks), per attack mode.
2. The profiler-identified bottleneck and the evidence for it.
3. Each experiment tried, with keep/revert verdict and the measured delta.
4. The exact diffs that landed (kernel and/or tuning-DB), and confirmation all correctness
   gates pass.
5. An honest statement of whether the kernel is at the hardware roofline and where any
   remaining headroom is (including for `a0`/`a1`, which you should at least scope even if
   the deep work stays on `a3`).
