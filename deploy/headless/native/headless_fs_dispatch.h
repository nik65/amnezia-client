#pragma once

namespace headless_fs {
// argv[0] is the caller name; only fixed filesystem/journal commands follow.
// No Qt application, socket, daemon, shell, or interpreter is started.
int dispatch(int argc, char** argv);
}
