#pragma once
#include <functional>
#include <string>
namespace amnezia::awgMigration {
// Reader returns the next bounded bytes; empty means EOF. It must honor its own deadline.
using PolicyEpochReader = std::function<std::string()>;
void validateRoutedPolicyEpochResponse(const PolicyEpochReader &reader, const std::string &revision, const std::string &hash);
int routedPolicyEpochCapabilityMain();
int checkRoutedPolicyEpochMain(const std::string &revision, const std::string &hash);
}
