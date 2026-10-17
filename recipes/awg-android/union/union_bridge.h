// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdint.h>
int amnezia_union_protect(uintptr_t bridge, int fd);
int amnezia_union_owner(uintptr_t bridge, int protocol, const void *source, int source_length,
                int source_port, const void *destination, int destination_length, int destination_port);
void amnezia_union_release(uintptr_t bridge);
