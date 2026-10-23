#pragma once
#include <string>

namespace amnezia::awgMigration {
// Private runtime transport: result contains config fields, including key material.
// Callers must keep stdin/stdout private; errors never include source content.
std::string configRuntimeRequest(const std::string &raw);
int configJsonMain();
}
