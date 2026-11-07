#pragma once
namespace amnezia::awgMigration::orchestration {
// Dispatches explicit orchestration modes only. Other feed/control argv retain
// their existing meaning. Handler status is returned without normalization.
bool runOrchestrationArgv(int argc, char **argv, int &status);
}
