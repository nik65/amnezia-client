#pragma once
#include "ready_config.h"
#include "trusted_image.h"
namespace amnezia::awgMigration {
// Read-only attestation. Every failure is deliberately secret-free.
void validateReadyTarget(ProcessRunner &, json_object *state, const ReadyConfig &source,
                         const ReadyConfig &target, bool automatic);
void validateExistingTarget(const std::string &directory, json_object *value,
                            json_object *ready, ProcessRunner &);
}
