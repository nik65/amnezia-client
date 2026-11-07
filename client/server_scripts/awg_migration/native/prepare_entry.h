#pragma once
#include "prepare_sequencer.h"
#include <filesystem>
#include <string>

namespace amnezia::awgMigration::prepareEntry {
struct Parsed {
    prepare::Request request;
    std::filesystem::path nativeFeed;
    std::filesystem::path nativeCollector;
    bool help = false;
    bool valid = false;
    std::string error;
};

// Exact CLI surface of the reviewed prepare operation. No positional, hidden
// or unimplemented option is accepted. `--native-feed` is the captured ELF
// path; `--native-feed-sha256` is its exact digest.
Parsed parseArgv(int argc, char **argv);

// Real dispatcher: validation, phase ordering, journal and cleanup are the
// canonical S1 sequencer. Ports are the only injected boundary. Returns 0 on
// a genuinely prepared generation, 2 on usage, 23 on failed work.
int run(const Parsed &, const std::filesystem::path &root,
        prepare::ObservationPort &, prepare::EffectPort &,
        prepare::AutomaticPlannerPort * = nullptr);

// Production entry, defined in production_main.cpp. It constructs the concrete
// POSIX adapters and never accepts a test seam or executable/argv override.
int productionMain(int argc, char **argv);
} // namespace amnezia::awgMigration::prepareEntry
