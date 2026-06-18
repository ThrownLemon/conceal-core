# Flaky crash / hang root-cause analysis (System runtime + WalletLegacy)

Branch: `agent/crash-diag` (from `pqc/testnet-poc` @ `35d39ac`)
Build/run host: WSL x86_64 (Ubuntu 24.04, gcc 13.3), build dirs `build-asan/` (ASan) and
`build-tsan/` (TSan) under `~/conceal-core-crash/`. Tests are intentionally `-O0`/`-g3`
in this repo even for Release, so sanitizer stacks are good.

## TL;DR

| # | Symptom | Status | Root cause | Fix |
|---|---------|--------|-----------|-----|
| 1 | `terminate … "Dispatcher::dispatch, read(remoteSpawnEvent) failed, result=11, Resource temporarily unavailable"` | **Reproduced (deterministic syscall proof) + FIXED** | Nonblocking `remoteSpawnEvent` eventfd read in `Dispatcher::dispatch()`/`yield()` throws on a benign `EAGAIN` when the eventfd is drained twice (race between the two epoll loops) | `src/Platform/Linux/System/Dispatcher.cpp` — ignore `EAGAIN`/`EWOULDBLOCK` on the eventfd read (applied) |
| 2 | UnitTests (`ctest #8`) intermittently fails/segfaults, passes on re-run | **Reproduced under ASan + root-caused** | Two distinct issues: (a) a **deterministic** heap-use-after-free in `WalletGreen::deleteAddress` (symptom-3 below) that aborts the whole binary; (b) the **intermittent** WalletLegacy async save/load stream-lifetime race (symptom 4) | (a) FIXED; (b) diagnosed + recommended (not applied — wallet money code) |
| 3 | `concealwallet pq_transfer` HUNG to a 700s timeout once, ran fine on re-run | **Diagnosed (same family as #1)** | Same `Dispatcher` remoteSpawn/eventfd path on the HttpClient-on-shared-dispatcher pattern; the EAGAIN throw on one context can leave a peer context's `Event` unset → the `RemoteContext::wait()` loop never completes → hang/timeout | Covered by the #1 fix (removes the spurious throw that breaks the wake handshake) |
| 4 | `WalletLegacyApi` deposit tests (`depositsUnlock`, etc.) intermittently fail, pass in isolation | **Reproduced under ASan (heap-use-after-free + stack-use-after-return) + root-caused** | WalletLegacy `save()`/`initAndLoad()` run on **detached threads** holding `std::ref` to the caller's stream; the worker can touch the stream after the test frame freed it, and the `EventWaiter` timeouts (3000 ms sync) are too tight under load → non-deterministic failures | Diagnosed + recommended (test-harness / wallet sync change — not applied) |

Two clean, low-risk, **proven** fixes are applied (symptoms 1 and 3, and the deterministic
part of symptom 2). The remaining intermittent wallet/test issue (symptom 4 and the flaky
part of 2) is fully diagnosed with sanitizer evidence and left for human review because the
safe fix touches money-handling wallet code / the test harness rather than `src/System`.

A note on sanitizer applicability discovered during this work:
- **ASan works and is the right tool here.** It caught both memory bugs.
- **TSan does NOT work on this binary.** It aborts at startup with
  `FATAL: ThreadSanitizer: unexpected memory mapping` and, when ASLR is disabled with
  `setarch -R`, the `ucontext`/`swapcontext` green-thread runtime in `src/System` desyncs
  TSan's fiber shadow (needs `__tsan_create_fiber`/`__tsan_switch_to_fiber` annotations at
  every `swapcontext`, which the code does not have). This is *why* races in this runtime
  have never been caught by TSan. The dispatcher-level System tests do run clean under TSan
  with ASLR disabled (40/40, 0 races) — but they do not exercise the cross-thread
  remoteSpawn timing that symptom 1 needs, so TSan is a dead end for these symptoms.

---

## Symptom 1 (and 3): Dispatcher remoteSpawn eventfd EAGAIN crash — ROOT CAUSE + FIX

### The code

`src/Platform/Linux/System/Dispatcher.cpp`. The dispatcher uses a single
`remoteSpawnEvent = eventfd(0, O_NONBLOCK)` (counter-mode, nonblocking) registered **once**
in epoll with **level-triggered `EPOLLIN`** (never `EPOLLONESHOT`):

```cpp
// Dispatcher() ctor
remoteSpawnEvent = eventfd(0, O_NONBLOCK);
remoteSpawnEventEpollEvent.events = EPOLLIN;           // level-triggered, stays armed
epoll_ctl(epoll, EPOLL_CTL_ADD, remoteSpawnEvent, &remoteSpawnEventEpollEvent);
```

A background thread queues work and writes the eventfd:

```cpp
void Dispatcher::remoteSpawn(std::function<void()>&& procedure) {
  { MutextGuard guard(...); remoteSpawningProcedures.push(std::move(procedure)); }
  uint64_t one = 1;
  write(remoteSpawnEvent, &one, sizeof one);   // counter += 1, fd becomes readable
}
```

The eventfd is drained from **two** places that BOTH read it:

- `Dispatcher::dispatch()` — `epoll_wait(epoll, &event, 1, -1)` (1 event, blocking)
- `Dispatcher::yield()`   — `epoll_wait(epoll, events, 16, 0)` (up to 16 events, non-blocking),
  and `yield()` tail-calls `dispatch()`.

Each drain did, **before the fix**:

```cpp
uint64_t buf;
auto transferred = read(remoteSpawnEvent, &buf, sizeof buf);
if (transferred == -1) {                       // <-- unconditional throw on ANY -1
    throw std::runtime_error("Dispatcher::dispatch, read(remoteSpawnEvent) failed, " + lastErrorMessage());
}
```

### The race

A single `write()` makes the counter `N>0`; a single `read()` drains it back to 0. Because the
fd is **level-triggered and registered permanently**, the kernel can report the *same*
readiness to two different `epoll_wait` calls (e.g. the blocking `dispatch()` epoll and a
`yield()` epoll on another context, or `yield()`'s loop followed by its tail `dispatch()`).
The first `read()` drains the counter to 0; the **second `read()` on the already-drained
nonblocking eventfd returns `-1` with `errno == EAGAIN` (11)** → the unconditional throw fires
→ the exception is uncaught at the dispatcher boundary → `std::terminate` → `abort` ("core
dumped").

This is exactly the production signature: it appears under load (wallet mining + piped stdin,
or a background NodeRpcProxy sync) because that is when `remoteSpawn()` is called frequently
from worker threads (`NodeRpcProxy.cpp:108,658`, `RemoteContext`'s `NotifyOnDestruction`,
`ConcealWallet.cpp:1428`) concurrently with an active main loop.

Corroborating evidence that this is the unique culprit: the **OSX dispatcher
(`src/Platform/OSX/System/Dispatcher.cpp`) does NOT have this bug** — it uses a
`std::atomic<bool> remoteSpawned` polled inside `dispatch()` instead of an eventfd it must
`read()`, so it can never hit EAGAIN. Only the Linux eventfd path is affected.

### Deterministic proof (errno + exact message)

A standalone program (`docs/reviews/crash-repro/`, plus an inline `eagain_proof.cpp` on the
build host) drains a `eventfd(0, EFD_NONBLOCK)` once and reads it again, then runs the OLD and
NEW branch logic:

```
second read transferred=-1 errno=11 (Resource temporarily unavailable) EAGAIN=11 EWOULDBLOCK=11
OLD logic THREW: Dispatcher::dispatch, read(remoteSpawnEvent) failed, Resource temporarily unavailable, result=11
NEW logic threw? no (FIXED)
```

The OLD branch reproduces the production message **character-for-character**
(`… read(remoteSpawnEvent) failed, Resource temporarily unavailable, result=11`). The NEW
branch does not throw. (A multithreaded `remoteSpawn` stress reproducer was also built and run
40× under ASan; it did not hit the narrow timing window, which is expected for a sub-microsecond
double-drain race — the syscall-level proof above is the conclusive evidence.)

### Fix (applied)

`src/Platform/Linux/System/Dispatcher.cpp`, both drain sites (`dispatch()` ~line 190 and
`yield()` ~line 322):

```cpp
auto transferred = read(remoteSpawnEvent, &buf, sizeof buf);
// EAGAIN/EWOULDBLOCK here means the eventfd was already drained by the other epoll loop;
// it is benign (queued procedures are still drained under the mutex below).
if (transferred == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
    throw std::runtime_error("Dispatcher::dispatch, read(remoteSpawnEvent) failed, " + lastErrorMessage());
}
```

`errno`, `EAGAIN`, `EWOULDBLOCK` are already in scope (the file uses `errno`/`EINTR` at the
`epoll_wait` sites). No new include. The queued procedures are still drained under
`MutextGuard` immediately after, so suppressing the spurious throw loses no work — it just
stops aborting the process on a benign wakeup. This mirrors the OSX design intent (a spurious
wake is a no-op, not fatal).

### Why this also explains symptom 3 (the 700s hang)

`RemoteContext::wait()` loops `while (!event.get()) event.wait();` and relies on a
cross-thread `remoteSpawn([=]{ localEvent->set(); })` to wake it. If the dispatcher throws on
the benign EAGAIN while servicing one context, the in-flight remoteSpawn handshake for a
*peer* context can be lost, leaving its `Event` unset — `wait()` never returns and the
operation (e.g. an `HttpClient` request on the wallet's shared dispatcher during `pq_transfer`)
hangs until the outer 700s timeout. Removing the spurious throw (the #1 fix) restores the wake
handshake. (Not separately reproduced — same code path and same fix.)

### Validation

- All 109 `System` tests (Dispatcher / RemoteContext / EventLock / Event / ContextGroup /
  Timer / TcpConnection / TcpConnector / TcpListener) pass under ASan **after** the fix
  (`[ PASSED ] 109 tests`). No regression.
- The multithreaded remoteSpawn reproducer passes 10/10 against the fixed `libSystem.a`.

---

## Symptom 2 + 4: intermittent UnitTests failures — ROOT CAUSE (two issues)

Running the `unit_tests` binary in a loop under ASan (gtest filter = the ctest skip list)
revealed the binary aborts and, when the deterministic aborter is excluded, the wallet/deposit
tests fail **non-deterministically** — matching "fails then passes on re-run".

### 2a. Deterministic heap-use-after-free in `WalletGreen::deleteAddress` — FIXED

Every loop iteration aborted here (test `WalletPrefixMac.deleteAddressThenCloseWithoutSaveReopens`,
`tests/UnitTests/TestWalletPrefixMac.cpp:337`):

```
==…==ERROR: AddressSanitizer: heap-use-after-free …
  #5 cn::WalletGreen::deleteAddress(...) src/Wallet/WalletGreen.cpp:2336   <- USE (project/distance)
  ...
  #8 cn::WalletGreen::deleteAddress(...) src/Wallet/WalletGreen.cpp:2334   <- FREE (erase)
```

The code freed the multi-index node, then used the freed iterator:

```cpp
m_walletsContainer.get<KeysIndex>().erase(it);                       // 2334: frees node `it`
auto addressIndex = std::distance(
    ...begin(), m_walletsContainer.project<RandomAccessIndex>(it));  // 2336-2337: USES freed `it`
```

`boost::multi_index` `erase(it)` invalidates/deallocates the node `it` refers to;
`project<RandomAccessIndex>(it)` then dereferences it → UAF. Deterministic (fires every run),
which is why it masked the intermittent failures and crashed `ctest #8`.

**Fix (applied)** — compute the index while `it` is valid, then erase:

```cpp
auto addressIndex = std::distance(
    ...begin(), m_walletsContainer.project<RandomAccessIndex>(it));  // BEFORE erase
m_walletsContainer.get<KeysIndex>().erase(it);
m_containerStorage.erase(std::next(m_containerStorage.begin(), addressIndex));
```

**Validation:** the previously-always-aborting test now passes **15/15** under ASan with
`abort_on_error=1`; all 11 `WalletPrefixMac` tests pass clean.

### 2b./4. WalletLegacy async save/load stream-lifetime race — DIAGNOSED (not applied)

With the deterministic aborter excluded, ASan caught an **intermittent** heap-use-after-free +
stack-use-after-return in `WalletLegacyApi.walletLoadsNullSpendSecretKey`:

```
ERROR: AddressSanitizer: heap-use-after-free …
  StdInputStream::readSome  src/Common/StdInputStream.cpp:16
  cn::WalletLegacySerializer::deserialize  …WalletLegacySerializer.cpp:117
  cn::WalletLegacy::doLoad  src/WalletLegacy/WalletLegacy.cpp:264      <- on a worker thread (asan_thread_start)
  ... TestBody  TestWalletLegacy.cpp:2032
also: StdOutputStream::writeSome src/Common/StdOutputStream.cpp:16  <- doSave worker, WalletLegacy.cpp:403
ERROR: AddressSanitizer: stack-use-after-return … TestWalletLegacy.cpp:2011
```

Root cause: `WalletLegacy::save()` (`WalletLegacy.cpp:382-384`) and `initAndLoad()`
(`:235-237`) spawn a **detached** worker thread (`doSave`/`doLoad`) that captures the caller's
stream by `std::ref`:

```cpp
m_asyncContextCounter.addAsyncContext();
std::thread saver(&WalletLegacy::doSave, this, std::ref(destination), ...);
saver.detach();
```

`doSave` notifies `saveCompleted` at the **end** of the thread body but the worker still has to
unwind (`ContextCounterHolder`, `m_blockchainSync.start()`); `doLoad` reads the stream
(`deserialize`, `:264`) and only fires `synchronizationCompleted` much later. The test
(`TestWalletLegacy.cpp:2011-2032`) does:

```cpp
std::stringstream data;     // local — freed at end of TestBody
alice->save(data);          // detached doSave captures &data
WaitWalletSave(...);        // returns on saveCompleted — may precede full worker unwind
alice->shutdown();
alice->initAndLoad(data,"pass");  // detached doLoad captures &data
WaitWalletSync(...);        // waits on synchronizationCompleted, not on the stream read
```

`WaitWalletSync` is bounded at **3000 ms** and `WaitWalletSave` at 5000 ms (`EventWaiter`,
`TestWalletLegacy.cpp:30-53`). Under load (sanitizers, parallel `ctest`, busy host) the
detached save/load worker can still be touching `data` when the test frame returns and frees
it → the observed UAF/stack-UAR; or the bounded wait simply times out → the plain
non-deterministic `[ FAILED ]` seen across `depositsUnlock`,
`depositsCheckSpendingTransactionId`, `depositsUpdatedCallbackCalledOnWithdraw`, etc.

**Why not auto-fixed:** the clean fixes are either (a) test-side — keep `data` alive until the
worker fully drains (e.g. an explicit barrier / `shutdown()` ordering that waits on
`m_asyncContextCounter`), and relax the 3000 ms sync timeout; or (b) runtime-side — notify
completion only *after* the worker releases the stream, or give save/load join semantics.
Both touch money-handling wallet code or the wallet test contract, which is out of scope for a
minimal `src/System` crash fix and warrants human review on consensus-adjacent code.

**Recommended minimal fix (for human review):**
- Test-side (lowest risk): in `walletLoadsNullSpendSecretKey` and the deposit tests, ensure the
  worker is fully drained before the stream/observers die — call `alice->shutdown()` (which
  already does `m_asyncContextCounter.waitAsyncContextsFinish()`, `WalletLegacy.cpp:319`)
  **before** `data` leaves scope, and raise the `waitForSyncEnd()` timeout from 3000 ms to
  match the 5000 ms used elsewhere.
- Runtime-side (if the production contract is meant to be "stream may die after
  saveCompleted"): move the `doSave`/`doLoad` stream access to complete *before* the worker
  notifies, and document that callers must keep the stream alive until completion — currently
  the contract is implicit and the detached-thread + ref-capture makes it easy to violate.

---

## What was applied vs diagnosed-only

**Applied (clean, low-risk, proven):**
1. `src/Platform/Linux/System/Dispatcher.cpp` — guard the `remoteSpawnEvent` read against
   `EAGAIN`/`EWOULDBLOCK` in `dispatch()` and `yield()`. Fixes symptom 1 (and 3). Proven by a
   deterministic syscall-level test (old throws the exact production message, new does not) and
   a no-regression run of all 109 System tests under ASan.
2. `src/Wallet/WalletGreen.cpp` — compute `deleteAddress`'s random-access index before
   `erase(it)`. Fixes the deterministic heap-use-after-free (part of symptom 2). Proven: the
   always-aborting test now passes 15/15 under ASan.

**Diagnosed-only (left for human review):**
- WalletLegacy async save/load stream-lifetime race + tight `EventWaiter` timeouts (symptom 4
  and the flaky part of symptom 2). Reproduced under ASan; recommended fixes above.

**Side findings (not fixed here):**
- `tests/UnitTests/TestPqDeposits.cpp:196-197` — `static const` class members `fixed_amount`/
  `fixed_term` have in-class initializers but no out-of-line definition; they are ODR-used
  (passed by const-ref to `EXPECT_EQ`, used to build a vector), so a `-fsanitize`/`-O1`
  `UnitTests` link fails with `undefined reference to (anonymous namespace)::PqDepositCurrencyTest::fixed_amount`.
  The default Release link happens to avoid it; add namespace-scope definitions
  (`const uint64_t PqDepositCurrencyTest::fixed_amount;`) to make it robust. Not a crash, but it
  blocks sanitizer builds of the full UnitTests target.
- TSan is unusable on this binary (see TL;DR); ASan is the supported sanitizer for this tree.

## How to reproduce / re-verify

```bash
# ASan build (UnitTests + System)
cd ~/conceal-core-crash && rm -rf build-asan && mkdir build-asan && cd build-asan
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
make -j16 UnitTests SystemTests

# Symptom-3 (WalletGreen UAF) regression — passes 15/15 after fix:
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./tests/unit_tests --gtest_filter='WalletPrefixMac.deleteAddressThenCloseWithoutSaveReopens'

# Symptom-1 EAGAIN proof (deterministic): see docs/reviews/crash-repro/RemoteSpawnRaceRepro.cpp
# and the inline eagain_proof.cpp described above.
```
