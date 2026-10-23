// Link boundary for isolated updater/coordinator tests. Never starts a command.
#include "vpnBackend.h"

namespace amnezia::headless {
struct RealCommandRunner::RunningProcess {};
RealCommandRunner::RealCommandRunner(QString root) : m_processes(std::make_unique<RunningProcess>()), m_stagingRoot(std::move(root)) {}
RealCommandRunner::~RealCommandRunner() = default;
bool RealCommandRunner::isAvailable(const QString &) const { return false; }
QString RealCommandRunner::resolveExecutable(const QStringList &) const { return {}; }
CommandResult RealCommandRunner::run(const QString &, const QStringList &) { return { false, -1, "TEST_BOUNDARY_NO_COMMAND", {} }; }
CommandResult RealCommandRunner::runBatch(const QString &, const QList<QStringList> &) { return { false, -1, "TEST_BOUNDARY_NO_COMMAND", {} }; }
CommandResult RealCommandRunner::runCaptured(const QString &, const QStringList &) { return { false, -1, "TEST_BOUNDARY_NO_COMMAND", {} }; }
CommandResult RealCommandRunner::startDetached(const QString &, const QStringList &) { return { false, -1, "TEST_BOUNDARY_NO_COMMAND", {} }; }
CommandResult RealCommandRunner::start(const QString &, const QString &, const QStringList &) { return { false, -1, "TEST_BOUNDARY_NO_COMMAND", {} }; }
CommandResult RealCommandRunner::stop(const QString &) { return { false, -1, "TEST_BOUNDARY_NO_COMMAND", {} }; }
bool RealCommandRunner::isSessionAlive(const QString &) const { return false; }
}
