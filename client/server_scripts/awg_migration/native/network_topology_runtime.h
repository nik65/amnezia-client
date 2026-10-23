#pragma once
#include "network_observer.h"
#include <string>

namespace amnezia::awgMigration {
std::string networkTopologyRuntimeRequest(const std::string &);
std::string networkTopologyRuntimeRequest(const std::string &, const NetworkObserverRunner &);
int networkTopologyJsonMain();
int networkTopologyJsonMain(const NetworkObserverRunner &);
}
