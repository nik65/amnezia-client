#include "route.hpp"
#include <cstdio>
int main(int argc, char **argv)
{
    try {
        collector_route::Args args;
        for (int i = 1; i < argc; ++i)
            args.emplace_back(argv[i]);
        collector_route::PosixAdapter adapter;
        collector_route::cli(adapter, args);
        return 0;
    } catch (...) {
        std::fputs("collector route reconciliation refused\n", stderr);
        return 1;
    }
}
