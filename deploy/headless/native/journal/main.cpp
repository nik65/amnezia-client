#include "journal.hpp"
#include <cstdio>
int main(int argc,char** argv) {
    try {
        QStringList args;
        for(int i=1;i<argc;++i) args.append(QString::fromLocal8Bit(argv[i]));
        return headless_journal::dispatch(args);
    } catch(const std::exception& e) {
        std::fprintf(stderr,"headless journal: %s\n",e.what()); return 1;
    }
}
