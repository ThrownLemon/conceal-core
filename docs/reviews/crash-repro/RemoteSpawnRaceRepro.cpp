// Targeted reproducer for the intermittent Dispatcher remoteSpawn eventfd EAGAIN crash.
//
// Symptom (production): concealwallet aborts with
//   terminate ... "Dispatcher::dispatch, read(remoteSpawnEvent) failed, result=11,
//   Resource temporarily unavailable"
// result=11 == EAGAIN on the nonblocking remoteSpawn eventfd read.
//
// This standalone program hammers the cross-thread remoteSpawn() path (the same one
// NodeRpcProxy / RemoteContext use) from many worker threads while the dispatcher main
// context repeatedly yield()s, maximizing the chance that two epoll_wait() calls
// (one in dispatch(), one in yield()) observe the eventfd readable at once and the
// second read() returns EAGAIN.
//
// Exit codes:
//   0  = survived all iterations (fix present / race not hit this run)
//   42 = caught the EAGAIN runtime_error  (race reproduced)
//   1  = some other failure
//
// NOT added to ctest; built ad hoc during crash diagnosis.

#include <System/Dispatcher.h>
#include <System/ContextGroup.h>
#include <System/Event.h>
#include <System/Timer.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace platform_system;

int main(int argc, char** argv) {
  const int rounds = (argc > 1) ? std::atoi(argv[1]) : 2000;
  const int threadsPerRound = (argc > 2) ? std::atoi(argv[2]) : 8;

  try {
    Dispatcher dispatcher;
    std::atomic<bool> stop(false);

    ContextGroup cg(dispatcher);

    // Main "spinner" context: keep the dispatcher busy yielding so that yield()'s
    // epoll_wait and dispatch()'s epoll_wait both race on the remoteSpawn eventfd.
    cg.spawn([&] {
      while (!stop.load(std::memory_order_relaxed)) {
        dispatcher.yield();
      }
    });

    for (int r = 0; r < rounds; ++r) {
      // Fire many cross-thread remoteSpawn() calls "simultaneously": each worker
      // thread writes the eventfd, the dispatcher drains it from two code paths.
      std::vector<std::thread> workers;
      std::atomic<int> ready(0);
      std::atomic<bool> go(false);
      Event done(dispatcher);
      std::atomic<int> remaining(threadsPerRound);

      for (int t = 0; t < threadsPerRound; ++t) {
        workers.emplace_back([&] {
          ready.fetch_add(1, std::memory_order_relaxed);
          while (!go.load(std::memory_order_relaxed)) { /* spin to align */ }
          // cross-thread remoteSpawn — the production crash path
          dispatcher.remoteSpawn([&] {
            if (remaining.fetch_sub(1, std::memory_order_relaxed) == 1) {
              done.set();
            }
          });
        });
      }

      while (ready.load(std::memory_order_relaxed) < threadsPerRound) { /* wait */ }
      go.store(true, std::memory_order_relaxed);

      // Let the dispatcher run other contexts until all spawned procedures fired.
      done.wait();

      for (auto& w : workers) w.join();

      if ((r % 200) == 0) {
        std::fprintf(stderr, "round %d/%d ok\n", r, rounds);
      }
    }

    stop.store(true, std::memory_order_relaxed);
    // nudge the spinner so it observes stop
    dispatcher.remoteSpawn([] {});
    cg.wait();

    std::fprintf(stderr, "SURVIVED all %d rounds\n", rounds);
    return 0;
  } catch (const std::runtime_error& e) {
    std::fprintf(stderr, "RUNTIME_ERROR: %s\n", e.what());
    if (std::strstr(e.what(), "remoteSpawnEvent") != nullptr) {
      std::fprintf(stderr, "REPRODUCED: remoteSpawnEvent EAGAIN crash\n");
      return 42;
    }
    return 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "EXCEPTION: %s\n", e.what());
    return 1;
  }
}
