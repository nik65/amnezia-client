#pragma once
#include <filesystem>
#include <string>

namespace amnezia::awgMigration {
// The directory is supplied by the trusted transport, never by request JSON.
// Production dispatch always uses /migration; owned tests supply a private root.
std::string controlRuntimeRequest(const std::string &raw, const std::filesystem::path &directory);
int controlJsonMain(const std::filesystem::path &directory = "/migration");
}
