// Copyright (c) 2023 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

// Copyright (c) 2024 AmneziaVPN
// This file has been modified for AmneziaVPN
//
// This file is based on the work of the Private Internet Access Desktop Client.
// The original code of the Private Internet Access Desktop Client is copyrighted (c) 2023 Private Internet Access, Inc. and licensed under GPL3.
//
// The modified version of this file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file. If not, see <https://www.gnu.org/licenses/>.

#include "linuxfirewall.h"
#include "logger.h"
#include "xray_defs.h"
#include <QElapsedTimer>
#include <QFileInfo>
#include <QHash>
#include <QProcess>
#include <QSet>
#include <QVector>

#define BRAND_CODE "amn"

namespace {
Logger logger("LinuxFirewall");
}  // namespace

namespace
{
const QString kAnchorName{BRAND_CODE "vpn"};
const QString kPacketTag{"0x3211"};
const QString kCGroupId{"0x567"};
const QString enabledKeyTemplate = "enabled:%1:%2";
const QString disabledKeyTemplate = "disabled:%1:%2";
const QString kVpnGroupName = BRAND_CODE "vpn";
QHash<QString, LinuxFirewall::FilterCallbackFunc> anchorCallbacks;
}

QString LinuxFirewall::kRtableName = QStringLiteral("%1rt").arg(kAnchorName);
QString LinuxFirewall::kOutputChain = QStringLiteral("OUTPUT");
QString LinuxFirewall::kPostRoutingChain = QStringLiteral("POSTROUTING");
QString LinuxFirewall::kPreRoutingChain = QStringLiteral("PREROUTING");
QString LinuxFirewall::kRootChain = QStringLiteral("%1.anchors").arg(kAnchorName);
QString LinuxFirewall::kFilterTable = QStringLiteral("filter");
QString LinuxFirewall::kNatTable = QStringLiteral("nat");
QString LinuxFirewall::kRawTable = QStringLiteral("raw");
QString LinuxFirewall::kMangleTable = QStringLiteral("mangle");

static QString getCommand(LinuxFirewall::IPVersion ip)
{
    return ip == LinuxFirewall::IPv6 ? QStringLiteral("ip6tables") : QStringLiteral("iptables");
}

int LinuxFirewall::createChain(LinuxFirewall::IPVersion ip, const QString& chain, const QString& tableName)
{
    if (ip == Both)
    {
        int result4 = createChain(IPv4, chain, tableName);
        int result6 = createChain(IPv6, chain, tableName);
        return result4 ? result4 : result6;
    }
    const QString cmd = getCommand(ip);
    // Creation never flushes an existing chain (including a competing writer
    // appearing after the absent-state observation).
    return executeIptables(cmd, {QStringLiteral("-t"), tableName, QStringLiteral("-N"), chain});
}

int LinuxFirewall::linkChain(LinuxFirewall::IPVersion ip, const QString& chain, const QString& parent, bool mustBeFirst, const QString& tableName)
{
    if (ip == Both)
    {
        int result4 = linkChain(IPv4, chain, parent, mustBeFirst, tableName);
        int result6 = linkChain(IPv6, chain, parent, mustBeFirst, tableName);
        return result4 ? result4 : result6;
    }
    const QString cmd = getCommand(ip);
    if (mustBeFirst)
    {
        // This monster shell script does the following:
        // 1. Check if a rule with the appropriate target exists at the top of the parent chain
        // 2. If not, insert a jump rule at the top of the parent chain
        // 3. Look for and delete a single rule with the designated target at an index > 1
        //    (we can't safely delete all rules at once since rule numbers change)
        // TODO: occasionally this script results in warnings in logs "Bad rule (does a matching rule exist in the chain?)" - this happens when
        // the e.g OUTPUT chain is empty but this script attempts to delete things from it anyway. It doesn't cause any problems, but we should still fix at some point..
        return execute(QStringLiteral("if ! %1 -L %2 -n --line-numbers -t %4 2> /dev/null | awk 'int($1) == 1 && $2 == \"%3\" { found=1 } END { if(found==1) { exit 0 } else { exit 1 } }' ; then %1 -I %2 -j %3 -t %4 && %1 -L %2 -n --line-numbers -t %4 2> /dev/null | awk 'int($1) > 1 && $2 == \"%3\" { print $1; exit }' | xargs -r %1 -t %4 -D %2 ; fi").arg(cmd, parent, chain, tableName));
    }
    else
        return execute(QStringLiteral("if ! %1 -C %2 -j %3 -t %4 2> /dev/null ; then %1 -A %2 -j %3 -t %4; fi").arg(cmd, parent, chain, tableName));
}

// The checked priority implementation follows the snapshot helpers below.

bool LinuxFirewall::installAnchor(LinuxFirewall::IPVersion ip, const QString& anchor, const QStringList& rules, const QString& tableName,
                                     const FilterCallbackFunc& enableFunc, const FilterCallbackFunc& disableFunc)
{
    if (ip == Both)
    {
        const bool result4 = installAnchor(IPv4, anchor, rules, tableName, enableFunc, disableFunc);
        const bool result6 = installAnchor(IPv6, anchor, rules, tableName, enableFunc, disableFunc);
        return result4 && result6;
    }

    const QString cmd = getCommand(ip);
    const QString anchorChain = QStringLiteral("%1.a.%2").arg(kAnchorName, anchor);
    const QString actualChain = QStringLiteral("%1.%2").arg(kAnchorName, anchor);
    bool ok = true;

    // Start by defining a placeholder chain, which stays locked into place
    // in the root chain without being removed or recreated, ensuring the
    // intended precedence order.
    if (createChain(ip, anchorChain, tableName) != 0)
        ok = false;
    if (linkChain(ip, anchorChain, kRootChain, false, tableName) != 0)
        ok = false;

    if(enableFunc)
    {
        const QString key = enabledKeyTemplate.arg(tableName, anchor);
        if(!anchorCallbacks.contains(key)) anchorCallbacks[key] = enableFunc;
    }
    if(disableFunc)
    {
        const QString key = disabledKeyTemplate.arg(tableName, anchor);
        if(!anchorCallbacks.contains(key)) anchorCallbacks[key] = disableFunc;
    }

    // Create the actual rule chain, which we'll insert or remove from the
    // placeholder anchor when needed.
    if (createChain(ip, actualChain, tableName) != 0)
        ok = false;
    for (const QString& rule : rules)
    {
        if (execute(QStringLiteral("%1 -A %2 %3 -t %4").arg(cmd, actualChain, rule, tableName)) != 0)
            ok = false;
    }
    return ok;
}

namespace
{

// --- Synchronous teardown transaction ---------------------------------------
//
// This firewall owns a fixed, known set of chains plus exactly one jump into a
// fixed built-in chain per table.  Teardown therefore does not need one
// process per rule: a bounded `iptables-save` snapshot per address family
// establishes which of those exact objects exist, and one
// `iptables-restore --noflush` transaction per (family, table) removes only
// them. The snapshot is parsed, never replayed. Legacy restore rereads and
// rewrites its current table under the xtables lock; only the configured
// name-owned chains and exact parent jumps are targeted by this plan.
//
// Semantics relied upon (iptables 1.8.7, the release shipped by Ubuntu 22.04;
// the same sources build both xtables-legacy-multi and xtables-nft-multi, see
// iptables/Makefile.am):
//   * iptables-restore hands every line inside a table to the same
//     do_command() the command line front end uses, so -D/-F/-X are valid
//     input (iptables/iptables-restore.c:338-342, iptables/xtables.c:949).
//   * --noflush skips the implicit flush and deletion of user chains
//     (iptables/iptables-restore.c:232-240).
//   * A ':' line would set a policy or flush an existing chain
//     (iptables/iptables-restore.c:265-268), so the transactions below carry
//     no ':' lines and never set a policy.
//   * A failing line aborts the run with status 1 and "line N failed"
//     (iptables/iptables-restore.c:347-351); the caller propagates that.

// --- Bounded process adapter -------------------------------------------------
//
// Qt 6's QProcess has no read-buffer limit: readBufferSize()/setReadBufferSize()
// are QAbstractSocket / Qt 5 QIODevice API and are not part of QProcess in Qt 6
// (C2039 against Qt 6.10.1).  QProcess keeps reading into an unbounded internal
// buffer for as long as it is pumped, so the only supported way to bound memory
// is to drain both channels ourselves and retain at most
// kMaxSnapshotBytes of stdout / kMaxProcessStderrBytes of stderr.
//
// Time accounting: one absolute work budget (kWorkDeadlineMs) covers start,
// stdin, drain and exit and is measured from just before start() to the last
// drained byte.  It is not extended by the start/write/finish waits, and the
// post-deadline kill/reap is bounded separately (kCleanupBoundMs) and reported
// as cleanupElapsedMs, so the deadline is never silently inflated.
//
// stdin accounting: write() only copies into QProcess's own buffer, so its
// return value says nothing about what the child received.  bytesToWrite()
// reaching zero proves the bytes left Qt's buffer for the child's pipe; it does
// not prove the child consumed them, and it is not a semantic commit either.
// Bytes still buffered when the child is gone mean the payload was truncated.
// The child's exit status cannot stand in for delivery: an iptables-restore
// payload cut before COMMIT exits 1, and an empty payload can exit 0.  For the
// whole-table vs per-table atomicity of a partial payload see
// LINUX_FIREWALL_LOCKING_PARENT_REVIEW.md.
//
// capture accounting: a read failure and a deadline expiry are separate facts.
// error() is a single slot that a later wait overwrites from *inside* the wait,
// so a failed read is latched from the errorOccurred() signal at the point it
// happens and a timeout is never allowed to relabel it as a clean, complete
// capture.

// Needed by the latch below: QObject::connect (QProcess already inherits
// QObject) and the atomics that make the latch safe against a cross-thread
// emitter.
#include <QObject>
#include <atomic>

constexpr qsizetype kMaxSnapshotBytes = 4 * 1024 * 1024;
constexpr qsizetype kMaxProcessStderrBytes = 64 * 1024;
constexpr qsizetype kProcessReadChunkBytes = 64 * 1024;
constexpr int kWorkDeadlineMs = 30000;
constexpr int kCleanupBoundMs = 5000;
constexpr int kReadSliceMs = 200;
constexpr int kSnapshotAttempts = 2;
constexpr int kXtablesLockWaitSeconds = 5;

struct ProcessOutcome
{
    bool started = false;
    bool startFailed = false;        // the OS refused to start the program
    bool finished = false;           // exit observed before the work deadline
    bool crashed = false;            // Qt reported CrashExit
    bool timedOut = false;           // work deadline expired
    bool writeFailed = false;        // stdin was not delivered to the child in full
    bool readFailed = false;         // a channel read failed; the capture is incomplete
    bool overflowOut = false;        // stdout exceeded kMaxSnapshotBytes
    bool truncatedErr = false;       // stderr was truncated at the bound
    bool terminationComplete = true; // no child is left running afterwards
    int exitCode = -2;
    qint64 outBytes = 0;             // full stdout byte count, even when dropped
    qint64 errBytes = 0;             // full stderr byte count, even when dropped
    qint64 workElapsedMs = 0;        // start -> last drained byte (excludes cleanup)
    qint64 cleanupElapsedMs = 0;     // kill + reap, outside the work deadline
    QByteArray out;
    QByteArray err;
};

// Durable I/O error latch.
//
// QProcess::error() is a single slot and is not durable.  The blocking waits
// overwrite it with QProcess::Timedout from *inside* the wait, using setError()
// without a signal: qprocess_unix.cpp (v6.4.2) waitForReadyRead() lines 766-768
// and waitForBytesWritten() lines 815-817.  Those same waits pump the other
// channel (waitForReadyRead can return true for stderr data while stdout is the
// selected channel; waitForBytesWritten pumps both reads), so a read failure
// can be emitted during a wait that then reports success or a plain timeout.
// Reading error() afterwards can therefore see Timedout -- or nothing at all.
//
// errorOccurred() is emitted exactly when the error is recorded
// (qprocess.cpp setErrorAndEmit(), lines 889-895), so the event is latched at
// the instant it happens and cannot be overwritten by a later wait.  The
// connection is direct: the latch is set synchronously even if a subclass emits
// from another thread, which is why the flags are atomics.  The latch is
// declared before the QProcess it observes and the connection is scoped to that
// process object, so neither the process destructor nor a late emission can
// reach destroyed stack state.
struct ProcessErrorLatch
{
    std::atomic<bool> readFailed{false};
    std::atomic<bool> writeFailed{false};

    void observe(QProcess::ProcessError error) noexcept
    {
        switch (error) {
        case QProcess::ReadError:
            readFailed.store(true, std::memory_order_relaxed);
            break;
        case QProcess::WriteError:
            writeFailed.store(true, std::memory_order_relaxed);
            break;
        default:
            // FailedToStart/Crashed/Timedout are reported through their own
            // outcome fields; they must not be relabelled as channel failures.
            break;
        }
    }

    // Copy the latched facts into the outcome without ever clearing one that
    // was already observed.
    void applyTo(ProcessOutcome *outcome) const noexcept
    {
        if (readFailed.load(std::memory_order_relaxed))
            outcome->readFailed = true;
        if (writeFailed.load(std::memory_order_relaxed))
            outcome->writeFailed = true;
    }
};

// Kill (if still running) and reap the child inside kCleanupBoundMs.  Never
// extends the work deadline, and never claims success it did not observe: a
// child that survives the bound leaves terminationComplete == false.
void terminateChild(QProcess& process, ProcessOutcome* outcome)
{
    QElapsedTimer cleanup;
    cleanup.start();
    if (process.state() != QProcess::NotRunning) {
        process.kill();
        process.waitForFinished(kCleanupBoundMs);
    }
    outcome->terminationComplete = (process.state() == QProcess::NotRunning);
    outcome->cleanupElapsedMs = cleanup.elapsed();
}

// Take whatever is buffered on both channels, one bounded chunk at a time.
// Returns true when at least one byte was taken so the caller keeps draining
// instead of sleeping while data is still flowing.
bool drainChannels(QProcess& process, ProcessOutcome* outcome)
{
    bool took = false;
    for (const QProcess::ProcessChannel channel :
         {QProcess::StandardOutput, QProcess::StandardError}) {
        process.setReadChannel(channel);
        while (process.bytesAvailable() > 0) {
            const qint64 wanted = qMin<qint64>(process.bytesAvailable(), kProcessReadChunkBytes);
            QByteArray chunk;
            chunk.resize(int(wanted));
            const qint64 got = process.read(chunk.data(), wanted);
            if (got < 0) {
                // A negative read is a capture failure only when Qt reports it
                // as ReadError; a drained channel that has already been closed
                // also answers -1 (with UnknownError), which is simply "no more
                // data".  Check error() here, at the failing read, because any
                // later waitForReadyRead()/waitForFinished() timeout overwrites
                // the single error slot.
                if (process.error() == QProcess::ReadError)
                    outcome->readFailed = true;
                break;
            }
            if (got == 0)
                break;
            // read() may return less than requested; the chunk must be cut to
            // what was actually read before it is counted or appended.
            chunk.resize(int(got));
            took = true;
            if (channel == QProcess::StandardError) {
                outcome->errBytes += got;
                const qsizetype room = kMaxProcessStderrBytes - outcome->err.size();
                if (room > 0)
                    outcome->err.append(chunk.left(qMin<qsizetype>(room, qsizetype(got))));
            } else {
                outcome->outBytes += got;
                if (!outcome->overflowOut) {
                    if (outcome->outBytes > kMaxSnapshotBytes) {
                        outcome->overflowOut = true;
                        outcome->out.clear();
                    } else {
                        outcome->out.append(chunk);
                    }
                }
            }
        }
    }
    return took;
}

ProcessOutcome runProcess(const QString& program, const QStringList& arguments,
                          const QByteArray& standardInput,
                          int workDeadlineMs = kWorkDeadlineMs)
{
    ProcessOutcome outcome;
    // Declared before the process it observes: the connection is scoped to the
    // QProcess, so a late emission can never touch this latch after the process
    // object is gone, and the latch itself outlives every emission.
    ProcessErrorLatch errors;
    QProcess process;
    QObject::connect(&process, &QProcess::errorOccurred, &process,
                     [&errors](QProcess::ProcessError error) { errors.observe(error); },
                     Qt::DirectConnection);
    process.setProcessChannelMode(QProcess::SeparateChannels);
    process.setReadChannel(QProcess::StandardOutput);

    QElapsedTimer work;
    work.start();
    const auto remaining = [&work, workDeadlineMs]() {
        const qint64 left = qint64(workDeadlineMs) - work.elapsed();
        return int(qBound<qint64>(qint64(0), left, qint64(workDeadlineMs)));
    };

    process.start(program, arguments, QProcess::ReadWrite);
    if (!process.waitForStarted(qMax(1, remaining()))) {
        // FailedToStart is a definite answer from the OS; anything else means
        // the child was still starting when the budget ran out.
        if (process.error() == QProcess::FailedToStart)
            outcome.startFailed = true;
        else
            outcome.timedOut = true;
        outcome.workElapsedMs = work.elapsed();
        terminateChild(process, &outcome);
        outcome.exitCode = -2;
        return outcome;
    }
    outcome.started = true;

    // stdin.  write() only copies bytes into QProcess's own buffer, so a
    // successful write() proves nothing about what the child received.  A short
    // or failed flush leaves iptables-restore with a truncated (or empty)
    // payload; that is not a commit -- a payload cut before COMMIT exits 1,
    // while empty input can exit 0 -- so the exit status cannot be used to
    // infer delivery.  Every byte must leave Qt's buffer for the child's pipe
    // (bytesToWrite() == 0) before the input can be called complete, and that
    // still only means "handed to the pipe", not "consumed or committed".
    if (!standardInput.isEmpty()) {
        qint64 accepted = 0;
        while (accepted < standardInput.size()) {
            const qint64 wrote = process.write(standardInput.constData() + accepted,
                                               standardInput.size() - accepted);
            if (wrote <= 0) {
                outcome.writeFailed = true;
                break;
            }
            accepted += wrote;
        }
        // closeWriteChannel() is only a request: Qt still has to hand the
        // buffered bytes to the child.  Pump both channels while flushing so a
        // child that blocks on a full output pipe cannot stall the flush (which
        // would turn bounded retention into a deadline), and so bytes sitting
        // in Qt's own buffer are never confused with output already retained.
        process.closeWriteChannel();
        while (!outcome.writeFailed && !outcome.readFailed && process.bytesToWrite() > 0) {
            // The latch is the durable record: a WriteError can be emitted
            // inside a wait that then reports a timeout, and a ReadError can be
            // emitted while flushing because waitForBytesWritten() pumps both
            // read channels.
            errors.applyTo(&outcome);
            if (outcome.writeFailed || outcome.readFailed)
                break;
            const int budget = remaining();
            if (budget <= 0) {
                outcome.timedOut = true;
                break;
            }
            if (drainChannels(process, &outcome))
                continue;
            if (process.state() == QProcess::NotRunning)
                break;   // child gone with input still queued: delivery failed
            if (!process.waitForBytesWritten(qMin(budget, kReadSliceMs))) {
                errors.applyTo(&outcome);
                if (!outcome.writeFailed && !outcome.readFailed) {
                    // Fallback for the same slot error(), should a build report
                    // the error without the signal: the latch above is primary.
                    if (process.error() == QProcess::WriteError)
                        outcome.writeFailed = true;
                    else if (process.error() == QProcess::ReadError)
                        outcome.readFailed = true;
                }
                // Any other false result is just this slice expiring: the child
                // is reading slowly, so keep flushing and draining.
            }
        }
        // A WriteError can arrive on the very wait that empties the queue, so
        // the queue count alone is not a complete test.
        errors.applyTo(&outcome);
        // Whatever is still buffered here never reached the child, even if it
        // exited 0 in the meantime.
        if (process.bytesToWrite() > 0)
            outcome.writeFailed = true;
        if (outcome.writeFailed || outcome.readFailed || outcome.timedOut) {
            process.closeWriteChannel();
            outcome.workElapsedMs = work.elapsed();
            terminateChild(process, &outcome);
            drainChannels(process, &outcome);   // bounded residue, never unbounded
            outcome.truncatedErr = outcome.errBytes > outcome.err.size();
            outcome.finished = false;
            outcome.crashed = (process.exitStatus() != QProcess::NormalExit);
            outcome.exitCode = outcome.readFailed ? -5 : (outcome.timedOut ? -2 : -3);
            return outcome;
        }
    }
    process.closeWriteChannel();

    // Drain both channels until the child has exited *and* nothing is left
    // buffered.  Waiting for the exit first would deadlock any child that fills
    // a pipe buffer (Qt's waitForFinished() does not drain the channels).
    for (;;) {
        errors.applyTo(&outcome);
        if (outcome.readFailed)
            break;   // the capture is incomplete; never report it as finished
        const bool took = drainChannels(process, &outcome);
        errors.applyTo(&outcome);
        if (outcome.readFailed)
            break;
        if (process.state() == QProcess::NotRunning) {
            if (!drainChannels(process, &outcome))
                break;   // exited and fully drained
            if (outcome.readFailed)
                break;
            continue;
        }
        const int budget = remaining();
        if (budget <= 0) {
            outcome.timedOut = true;
            break;
        }
        if (took)
            continue;   // more data may already be buffered
        // A wait can emit ReadError on either channel and then overwrite
        // error() with Timedout before returning, and it can return true for
        // data on the channel that did not fail.  Neither return value nor the
        // final error() is therefore the failure record: the latch is.
        const bool ready = process.waitForReadyRead(qMin(budget, kReadSliceMs));
        errors.applyTo(&outcome);
        if (outcome.readFailed)
            break;
        if (!ready && process.error() == QProcess::ReadError) {
            outcome.readFailed = true;
            break;
        }
    }

    errors.applyTo(&outcome);
    const bool stillRunning = (process.state() != QProcess::NotRunning);
    outcome.workElapsedMs = work.elapsed();
    if (stillRunning) {
        // Outlived the work budget, lost the race at the very end, or the
        // capture failed while the child was still alive.  Only a budget
        // expiry gets the timeout label: this cleanup must not relabel a read
        // failure as an ordinary timeout.
        if (!outcome.readFailed)
            outcome.timedOut = true;
        terminateChild(process, &outcome);
        drainChannels(process, &outcome);   // bounded residue, never unbounded
    } else {
        outcome.terminationComplete = true;
    }
    outcome.truncatedErr = outcome.errBytes > outcome.err.size();
    outcome.finished = (!outcome.timedOut && !outcome.readFailed && !outcome.writeFailed &&
                        outcome.terminationComplete);
    outcome.crashed = (process.exitStatus() != QProcess::NormalExit);

    if (!outcome.terminationComplete)
        outcome.exitCode = -2;
    else if (outcome.readFailed)
        outcome.exitCode = -5;
    else if (outcome.timedOut)
        outcome.exitCode = -2;
    else if (outcome.writeFailed)
        outcome.exitCode = -3;
    else if (outcome.overflowOut)
        outcome.exitCode = -4;
    else if (outcome.crashed)
        outcome.exitCode = -1;
    else
        outcome.exitCode = process.exitCode();
    return outcome;
}

struct SavedChain
{
    QString name;
    QString policy;
    QVector<QStringList> rules;
};

struct SavedTable
{
    QString name;
    QStringList order;
    QHash<QString, SavedChain> chains;
};

struct Snapshot
{
    QStringList order;
    QHash<QString, SavedTable> tables;
};

bool refuse(QString* error, const QString& message)
{
    if (error != nullptr)
        *error = message;
    return false;
}

QString quoted(const QString& value)
{
    return QStringLiteral("'") + value + QStringLiteral("'");
}

bool splitTokens(const QString& line, QStringList* tokens)
{
    QString current;
    bool quotedValue = false;
    bool escaped = false;
    bool tokenStarted = false;
    for (const QChar character : line) {
        if (escaped) {
            current.append(character);
            escaped = false;
            tokenStarted = true;
            continue;
        }
        if (character == QLatin1Char('\\')) {
            escaped = true;
            tokenStarted = true;
            continue;
        }
        if (character == QLatin1Char('"')) {
            quotedValue = !quotedValue;
            tokenStarted = true;
            continue;
        }
        if (!quotedValue && character.isSpace()) {
            if (tokenStarted) {
                tokens->append(current);
                current.clear();
                tokenStarted = false;
            }
            continue;
        }
        current.append(character);
        tokenStarted = true;
    }
    if (escaped || quotedValue)
        return false;
    if (tokenStarted)
        tokens->append(current);
    return true;
}

QStringList jumpTargets(const QStringList& tokens)
{
    // Return *every* jump/goto candidate, not just the first.  iptables-save
    // does not preserve which token was a quoted extension argument, so a
    // comment whose value is literally "-j" (or "--goto=amnvpn.anchors") must
    // not be allowed to hide a later real jump.  False positives are refused;
    // a missed foreign reference is not.
    QStringList targets;
    for (int index = 0; index < tokens.size(); ++index) {
        const QString& token = tokens.at(index);
        if (token == QLatin1String("--jump=") || token == QLatin1String("--goto="))
            continue;
        if (token.startsWith(QLatin1String("--jump=")))
            targets.append(token.mid(7));
        else if (token.startsWith(QLatin1String("--goto=")))
            targets.append(token.mid(7));
        else if ((token == QLatin1String("-j") || token == QLatin1String("--jump") ||
                  token == QLatin1String("-g") || token == QLatin1String("--goto")) &&
                 index + 1 < tokens.size()) {
            targets.append(tokens.at(index + 1));
        }
    }
    return targets;
}

bool parseSnapshot(const QByteArray& raw, const QString& family, Snapshot* snapshot,
                   QString* error)
{
    // A complete successful save may contain no registered tables.
    if (raw.isEmpty())
        return true;
    if (!raw.endsWith('\n'))
        return refuse(error, QStringLiteral("%1: incomplete final snapshot line").arg(family));

    QString currentTable;
    int lineNumber = 0;
    const QStringList lines = QString::fromUtf8(raw).split(QLatin1Char('\n'));
    for (const QString& rawLine : lines) {
        ++lineNumber;
        const QString line = rawLine.trimmed();
        // These comments report present-but-invisible nft state, not absence.
        if (line.startsWith(QLatin1String("# Table ")) &&
            (line.contains(QLatin1String(" is incompatible")) ||
             line.contains(QLatin1String(" contains incompatible base-chains")))) {
            return refuse(error, QStringLiteral("%1: line %2: nft snapshot omits incompatible state")
                                     .arg(family).arg(lineNumber));
        }
        if (line.isEmpty() || line.startsWith(QLatin1Char('#')))
            continue;
        if (line == QLatin1String("COMMIT")) {
            if (currentTable.isEmpty())
                return refuse(error, QStringLiteral("%1: line %2: COMMIT outside a table")
                                         .arg(family).arg(lineNumber));
            if (snapshot->tables.value(currentTable).order.isEmpty())
                return refuse(error, QStringLiteral("%1: line %2: table %3 has no chain declarations")
                                         .arg(family).arg(lineNumber).arg(currentTable));
            currentTable.clear();
            continue;
        }
        if (line.startsWith(QLatin1Char('*'))) {
            if (!currentTable.isEmpty())
                return refuse(error, QStringLiteral("%1: line %2: table header inside a table")
                                         .arg(family).arg(lineNumber));
            const QString name = line.mid(1).trimmed();
            if (name.isEmpty() || name.contains(QLatin1Char(' ')))
                return refuse(error, QStringLiteral("%1: line %2: invalid table name")
                                         .arg(family).arg(lineNumber));
            if (snapshot->tables.contains(name))
                return refuse(error, QStringLiteral("%1: line %2: duplicate table %3")
                                         .arg(family).arg(lineNumber).arg(name));
            SavedTable table;
            table.name = name;
            snapshot->tables.insert(name, table);
            snapshot->order.append(name);
            currentTable = name;
            continue;
        }
        if (currentTable.isEmpty())
            return refuse(error, QStringLiteral("%1: line %2: content outside a table")
                                     .arg(family).arg(lineNumber));
        SavedTable& table = snapshot->tables[currentTable];
        if (line.startsWith(QLatin1Char(':'))) {
            QStringList tokens;
            if (!splitTokens(line.mid(1), &tokens) || tokens.size() < 2)
                return refuse(error, QStringLiteral("%1: line %2: malformed chain declaration")
                                         .arg(family).arg(lineNumber));
            const QString name = tokens.at(0);
            if (name.isEmpty() || table.chains.contains(name))
                return refuse(error, QStringLiteral("%1: line %2: duplicate or empty chain declaration")
                                         .arg(family).arg(lineNumber));
            SavedChain chain;
            chain.name = name;
            chain.policy = tokens.at(1);
            table.chains.insert(name, chain);
            table.order.append(name);
            continue;
        }
        QStringList tokens;
        if (!splitTokens(line, &tokens) || tokens.size() < 3 ||
            tokens.at(0) != QLatin1String("-A")) {
            return refuse(error, QStringLiteral("%1: line %2: unsupported save line %3")
                                     .arg(family).arg(lineNumber).arg(quoted(line.left(80))));
        }
        const QString name = tokens.at(1);
        if (!table.chains.contains(name))
            return refuse(error, QStringLiteral("%1: line %2: rule for undeclared chain %3")
                                     .arg(family).arg(lineNumber).arg(quoted(name)));
        table.chains[name].rules.append(tokens.mid(2));
    }
    if (!currentTable.isEmpty())
        return refuse(error, QStringLiteral("%1: COMMIT expected at end of snapshot").arg(family));
    if (snapshot->tables.isEmpty())
        return refuse(error, QStringLiteral("%1: snapshot contains no tables").arg(family));
    return true;
}

struct OwnedTable
{
    QString table;
    QString parent;
    QString root;
    QStringList anchors;
};

struct TableTransaction
{
    QString program;
    QString table;
    QStringList operations;
};

struct TeardownPlan
{
    QVector<TableTransaction> tables;
};

struct FamilyPlan
{
    QString family;
    QString saveProgram;
    QString restoreProgram;
    QVector<OwnedTable> tables;
};

QStringList filterAnchorNames(bool ipv6)
{
    // Same order as the previous teardown so the resulting chain order is
    // unchanged for anything that inspects it.
    QStringList anchors{QStringLiteral("000.allowLoopback"),
                        QStringLiteral("400.allowPIA")};
    if (!ipv6)
        anchors.append(QStringLiteral("320.allowDNS"));
    anchors.append(QStringLiteral("310.blockDNS"));
    anchors.append(QStringLiteral("300.allowLAN"));
    anchors.append(QStringLiteral("290.allowDHCP"));
    if (ipv6)
        anchors.append(QStringLiteral("250.blockIPv6"));
    anchors.append(QStringLiteral("200.allowVPN"));
    if (!ipv6)
        anchors.append(QStringLiteral("120.blockNets"));
    anchors.append(QStringLiteral("130.allowMarkedXray"));
    if (!ipv6)
        anchors.append(QStringLiteral("110.allowNets"));
    anchors.append(QStringLiteral("100.blockAll"));
    return anchors;
}

bool hasOwnedPrefix(const QString& chain)
{
    return chain == kAnchorName || chain.startsWith(kAnchorName + QLatin1Char('.'));
}

bool planTable(const SavedTable& table, const OwnedTable& owned, const QString& program,
               TeardownPlan* plan, QString* error)
{
    QSet<QString> expected;
    expected.insert(owned.root);
    for (const QString& anchor : owned.anchors) {
        expected.insert(QStringLiteral("%1.a.%2").arg(kAnchorName, anchor));
        expected.insert(QStringLiteral("%1.%2").arg(kAnchorName, anchor));
    }

    // Fail closed on anything that carries our namespace but is not one of the
    // chains this firewall creates.
    for (const QString& chain : table.order) {
        if (hasOwnedPrefix(chain) && !expected.contains(chain)) {
            return refuse(error, QStringLiteral("%1: chain %2 carries the firewall namespace "
                                                "but is not part of the known chain set")
                                     .arg(table.name, quoted(chain)));
        }
    }

    QVector<QStringList> parentJumps;
    for (const QString& holder : table.order) {
        const SavedChain chain = table.chains.value(holder);
        for (const QStringList& rule : chain.rules) {
            const QStringList targets = jumpTargets(rule);
            bool referencesOwned = false;
            for (const QString& target : targets) {
                if (expected.contains(target)) {
                    referencesOwned = true;
                    break;
                }
            }
            if (!referencesOwned)
                continue;
            if (holder == owned.parent) {
                // The parent jump must be exactly "-j amnvpn.anchors".  A -g,
                // --goto, comment value or any additional match means this is
                // not the rule this firewall created, so ownership is unknown.
                if (targets.size() != 1 || targets.first() != owned.root ||
                    rule != QStringList{QStringLiteral("-j"), owned.root}) {
                    return refuse(error, QStringLiteral("%1: %2 jumps to %3 but is not the exact "
                                                        "-j rule; refusing to guess ownership")
                                             .arg(table.name, quoted(holder), quoted(owned.root)));
                }
                parentJumps.append(rule);
                continue;
            }
            if (!expected.contains(holder)) {
                return refuse(error, QStringLiteral("%1: foreign chain %2 references %3; "
                                                    "removing it would change foreign policy")
                                         .arg(table.name, quoted(holder), quoted(targets.first())));
            }
        }
    }
    if (parentJumps.size() > 1) {
        return refuse(error, QStringLiteral("%1: %2 jump appears %3 times; ownership is ambiguous")
                                 .arg(table.name, quoted(owned.root))
                                 .arg(parentJumps.size()));
    }

    TableTransaction transaction;
    transaction.program = program;
    transaction.table = table.name;
    if (parentJumps.size() == 1)
        transaction.operations.append(QStringLiteral("-D %1 -j %2").arg(owned.parent, owned.root));
    if (table.chains.contains(owned.root)) {
        transaction.operations.append(QStringLiteral("-F %1").arg(owned.root));
        transaction.operations.append(QStringLiteral("-X %1").arg(owned.root));
    }
    for (const QString& anchor : owned.anchors) {
        const QString placeholder = QStringLiteral("%1.a.%2").arg(kAnchorName, anchor);
        const QString actual = QStringLiteral("%1.%2").arg(kAnchorName, anchor);
        if (table.chains.contains(placeholder)) {
            transaction.operations.append(QStringLiteral("-F %1").arg(placeholder));
            transaction.operations.append(QStringLiteral("-X %1").arg(placeholder));
        }
        if (table.chains.contains(actual)) {
            transaction.operations.append(QStringLiteral("-F %1").arg(actual));
            transaction.operations.append(QStringLiteral("-X %1").arg(actual));
        }
    }
    if (!transaction.operations.isEmpty())
        plan->tables.append(transaction);
    return true;
}

bool readSnapshot(const QString& program, const QString& family, QByteArray* out,
                  QString* error)
{
    QString lastError;
    for (int attempt = 0; attempt < kSnapshotAttempts; ++attempt) {
        const ProcessOutcome outcome = runProcess(program, {}, {});
        if (outcome.overflowOut) {
            return refuse(error, QStringLiteral("%1: %2 output exceeded the %3 byte limit")
                                     .arg(family, program)
                                     .arg(kMaxSnapshotBytes));
        }
        if (outcome.writeFailed) {
            return refuse(error, QStringLiteral("%1: %2 input could not be written").arg(family, program));
        }
        if (!outcome.terminationComplete) {
            return refuse(error, QStringLiteral("%1: %2 could not be terminated; capture is incomplete")
                                     .arg(family, program));
        }
        if (outcome.finished && outcome.exitCode == 0) {
            *out = outcome.out;
            return true;
        }
        lastError = QStringLiteral("%1: %2 exit %3: %4")
                        .arg(family, program)
                        .arg(outcome.exitCode)
                        .arg(QString::fromUtf8(outcome.err).trimmed());
        if (!outcome.started)
            break;
    }
    return refuse(error, lastError);
}

bool planFamily(const FamilyPlan& family, TeardownPlan* plan, QString* error)
{
    QByteArray raw;
    if (!readSnapshot(family.saveProgram, family.family, &raw, error))
        return false;
    Snapshot snapshot;
    if (!parseSnapshot(raw, family.family, &snapshot, error))
        return false;

    // Capture completeness is decided here, before any table-level question,
    // and it is never inferred from the number of tables in the snapshot.
    // `iptables-save` without -t prints "all available tables" (iptables-save(8))
    // and does not load a table that the kernel does not have loaded; a table
    // that is absent from a capture that is *proven complete* therefore cannot
    // hold any chain of ours, because every chain we create lives in exactly
    // these four tables.
    //
    // "Proven complete" is established by readSnapshot()/parseSnapshot():
    //   * the child exited normally (a truncated dump that hit EPIPE exits
    //     non-zero and is refused),
    //   * every produced byte was drained without hitting kMaxSnapshotBytes
    //     (overflowOut is refused, so no tail can be silently lost),
    //   * the child is gone (terminationComplete),
    //   * the snapshot is syntactically closed: every table block ends with
    //     COMMIT, no table is left open, no table is empty of chain
    //     declarations, and no content appears outside a table. A genuinely
    //     empty family is valid; nft omission markers are refused separately.
    // A cut inside a block or its final line is rejected here. A cut at a
    // complete block boundary remains the capture layer's responsibility.
    QStringList absentTables;
    for (const OwnedTable& owned : family.tables) {
        if (!snapshot.tables.contains(owned.table))
            absentTables.append(owned.table);
    }
    if (!absentTables.isEmpty()) {
        // Recorded, not assumed: the teardown proceeds for the tables that do
        // exist, and the operator can see why the others were skipped.  This is
        // what makes a fresh install (no nat/raw/mangle module loaded yet)
        // succeed while a truncated capture still fails.
        logger.info() << family.family << family.saveProgram
                      << "snapshot does not list" << absentTables
                      << "table(s); no chain of this firewall can exist there";
    }


    QSet<QString> ownedTables;
    for (const OwnedTable& owned : family.tables)
        ownedTables.insert(owned.table);

    for (const QString& tableName : snapshot.order) {
        if (ownedTables.contains(tableName))
            continue;
        const SavedTable table = snapshot.tables.value(tableName);
        for (const QString& chain : table.order) {
            if (hasOwnedPrefix(chain)) {
                return refuse(error, QStringLiteral("%1: chain %2 exists in the unowned table %3")
                                         .arg(family.family, quoted(chain), quoted(tableName)));
            }
        }
    }

    for (const OwnedTable& owned : family.tables) {
        if (!snapshot.tables.contains(owned.table))
            continue;
        if (!planTable(snapshot.tables.value(owned.table), owned, family.restoreProgram,
                       plan, error)) {
            return false;
        }
    }
    return true;
}

QByteArray transactionPayload(const TableTransaction& transaction)
{
    QString payload = QStringLiteral("*%1\n").arg(transaction.table);
    for (const QString& operation : transaction.operations)
        payload += operation + QLatin1Char('\n');
    payload += QStringLiteral("COMMIT\n");
    return payload.toUtf8();
}

// --- Read-only installation / targeted mutation contracts --------------------

QVector<OwnedTable> safetyTables(bool ipv6)
{
    // The order here is the actual installAnchor() insertion order, not the
    // teardown enumeration. Optional placeholders may be empty or enabled.
    QStringList filters{QStringLiteral("000.allowLoopback")};
    if (!ipv6) filters.append(QStringLiteral("320.allowDNS"));
    filters += {QStringLiteral("310.blockDNS"), QStringLiteral("300.allowLAN"),
                QStringLiteral("290.allowDHCP")};
    if (ipv6) filters.append(QStringLiteral("250.blockIPv6"));
    filters += {QStringLiteral("200.allowVPN"), QStringLiteral("130.allowMarkedXray")};
    if (!ipv6) filters += {QStringLiteral("120.blockNets"), QStringLiteral("110.allowNets")};
    filters += {QStringLiteral("400.allowPIA"), QStringLiteral("100.blockAll")};
    return {{QStringLiteral("filter"), QStringLiteral("OUTPUT"), QStringLiteral("amnvpn.anchors"), filters},
            {QStringLiteral("nat"), QStringLiteral("POSTROUTING"), QStringLiteral("amnvpn.anchors"), {QStringLiteral("100.transIp")}},
            {QStringLiteral("mangle"), QStringLiteral("OUTPUT"), QStringLiteral("amnvpn.anchors"), {QStringLiteral("100.tagPkts")}},
            {QStringLiteral("raw"), QStringLiteral("PREROUTING"), QStringLiteral("amnvpn.anchors"), {QStringLiteral("100.vpnTunOnly")}}};
}

QStringList immutableRules(const QString& anchor, bool ipv6)
{
    if (anchor == QLatin1String("000.allowLoopback")) return {QStringLiteral("-o lo+ -j ACCEPT")};
    if (anchor == QLatin1String("310.blockDNS")) return {QStringLiteral("-p udp --dport 53 -j REJECT"), QStringLiteral("-p tcp --dport 53 -j REJECT")};
    if (anchor == QLatin1String("300.allowLAN")) {
        if (ipv6) return {QStringLiteral("-d fc00::/7 -j ACCEPT"), QStringLiteral("-d fe80::/10 -j ACCEPT"), QStringLiteral("-d ff00::/8 -j ACCEPT")};
        return {QStringLiteral("-d 10.0.0.0/8 -j ACCEPT"), QStringLiteral("-d 169.254.0.0/16 -j ACCEPT"), QStringLiteral("-d 172.16.0.0/12 -j ACCEPT"), QStringLiteral("-d 192.168.0.0/16 -j ACCEPT"), QStringLiteral("-d 224.0.0.0/4 -j ACCEPT"), QStringLiteral("-d 255.255.255.255/32 -j ACCEPT")};
    }
    if (anchor == QLatin1String("290.allowDHCP")) return {ipv6 ? QStringLiteral("-p udp -d ff00::/8 --sport 546 --dport 547 -j ACCEPT") : QStringLiteral("-p udp -d 255.255.255.255 --sport 68 --dport 67 -j ACCEPT")};
    if (anchor == QLatin1String("250.blockIPv6")) return {QStringLiteral("! -o lo+ -j REJECT")};
    if (anchor == QLatin1String("200.allowVPN")) return {QStringLiteral("-o amn0+ -j ACCEPT"), QStringLiteral("-o tun0+ -j ACCEPT"), QStringLiteral("-o tun2+ -j ACCEPT")};
    if (anchor == QLatin1String("130.allowMarkedXray")) return {QStringLiteral("-m mark --mark %1 -j ACCEPT").arg(amnezia::xray::xrayTrafficMark)};
    if (anchor == QLatin1String("100.blockAll")) return {QStringLiteral("-j REJECT")};
    if (anchor == QLatin1String("100.tagPkts")) return {QStringLiteral("-m cgroup --cgroup %1 -j MARK --set-mark %2").arg(kCGroupId, kPacketTag)};
    return {}; // allow/block/DNS/PIA lists and NAT/raw rules are mutable.
}

// Only known iptables-save normalizations: protocol module insertion, default
// REJECT type, host prefixes, numeric marks/cgroups, set-mark -> set-xmark,
// and option ordering. Other tokens remain significant (including negation).
QStringList comparableRule(const QStringList& rule, bool ipv6)
{
    QStringList groups;
    for (int i = 0; i < rule.size(); ++i) {
        QString option = rule.at(i), negation;
        if (option == QLatin1String("!") && i + 1 < rule.size()) {
            negation = QStringLiteral("! "); option = rule.at(++i);
        }
        if (i + 1 >= rule.size()) { groups.append(negation + option); continue; }
        QString value = rule.at(++i);
        if (negation.isEmpty() && option == QLatin1String("-m") &&
            (value == QLatin1String("udp") || value == QLatin1String("tcp")) &&
            rule.contains(QStringLiteral("-p")) && rule.value(rule.indexOf(QStringLiteral("-p")) + 1) == value)
            continue;
        if (negation.isEmpty() && option == QLatin1String("--reject-with") &&
            value == (ipv6 ? QLatin1String("icmp6-port-unreachable") : QLatin1String("icmp-port-unreachable")) &&
            rule.contains(QStringLiteral("-j")) && rule.value(rule.indexOf(QStringLiteral("-j")) + 1) == QLatin1String("REJECT"))
            continue;
        if (option == QLatin1String("-d") &&
            (value.endsWith(QLatin1String("/32")) || value.endsWith(QLatin1String("/128"))))
            value = value.left(value.lastIndexOf(QLatin1Char('/')));
        if (option == QLatin1String("--set-mark")) {
            option = QStringLiteral("--set-xmark");
            if (!value.contains(QLatin1Char('/'))) value += QStringLiteral("/0xffffffff");
        }
        if (option == QLatin1String("--mark") || option == QLatin1String("--cgroup") || option == QLatin1String("--set-xmark")) {
            QStringList numbers = value.split(QLatin1Char('/'));
            for (QString& number : numbers) {
                bool ok = false; const uint n = number.toUInt(&ok, 0);
                if (ok) number = QString::number(n);
            }
            if (option == QLatin1String("--mark") && numbers.size() == 2 && numbers.last() == QStringLiteral("4294967295")) numbers.removeLast();
            value = numbers.join(QLatin1Char('/'));
        }
        groups.append(negation + option + QLatin1Char(' ') + value);
    }
    groups.sort();
    return groups;
}

bool sameRules(const QVector<QStringList>& actual, const QVector<QStringList>& expected, bool ipv6)
{
    if (actual.size() != expected.size()) return false;
    for (qsizetype i = 0; i < actual.size(); ++i)
        if (comparableRule(actual.at(i), ipv6) != comparableRule(expected.at(i), ipv6)) return false;
    return true;
}

bool observeFirewall(LinuxFirewall::IPVersion ip, Snapshot* snapshot)
{
    QByteArray raw; QString error;
    const QString program = ip == LinuxFirewall::IPv6 ? QStringLiteral("ip6tables-save") : QStringLiteral("iptables-save");
    if (ip == LinuxFirewall::Both || !readSnapshot(program, program, &raw, &error) ||
        !parseSnapshot(raw, program, snapshot, &error)) {
        logger.error() << "Firewall observation failed:" << error;
        return false;
    }
    return true;
}

bool completeFirewall(const Snapshot& snapshot, bool ipv6)
{
    const QVector<OwnedTable> owned = safetyTables(ipv6);
    for (const QString& tableName : snapshot.order) {
        bool known = false;
        for (const OwnedTable& item : owned) if (item.table == tableName) known = true;
        if (!known) for (const QString& chain : snapshot.tables.value(tableName).order)
            if (hasOwnedPrefix(chain)) return false;
    }
    for (const OwnedTable& item : owned) {
        if (!snapshot.tables.contains(item.table)) return false;
        const SavedTable table = snapshot.tables.value(item.table);
        TeardownPlan ignored; QString error;
        if (!planTable(table, item, {}, &ignored, &error) || !table.chains.contains(item.parent)) return false;
        const auto parentRules = table.chains.value(item.parent).rules;
        if (parentRules.isEmpty() || parentRules.first() != QStringList{QStringLiteral("-j"), item.root}) return false;
        QVector<QStringList> rootRules;
        for (const QString& anchor : item.anchors) {
            const QString placeholder = kAnchorName + QStringLiteral(".a.") + anchor;
            const QString actual = kAnchorName + QLatin1Char('.') + anchor;
            if (!table.chains.contains(placeholder) || !table.chains.contains(actual) ||
                table.chains.value(placeholder).policy != QLatin1String("-") || table.chains.value(actual).policy != QLatin1String("-")) return false;
            rootRules.append({QStringLiteral("-j"), placeholder});
            const auto links = table.chains.value(placeholder).rules;
            if (!links.isEmpty() && links != QVector<QStringList>{{QStringLiteral("-j"), actual}}) return false;
            // Runtime replacement changes these singleton rules, not their
            // required presence. An empty NAT/raw chain is a partial install.
            if ((anchor == QLatin1String("100.transIp") || anchor == QLatin1String("100.vpnTunOnly")) &&
                table.chains.value(actual).rules.size() != 1) return false;
            const QStringList fixed = immutableRules(anchor, ipv6);
            if (!fixed.isEmpty()) {
                QVector<QStringList> rules;
                for (const QString& text : fixed) { QStringList tokens; if (!splitTokens(text, &tokens)) return false; rules.append(tokens); }
                if (!sameRules(table.chains.value(actual).rules, rules, ipv6)) return false;
            }
        }
        if (!table.chains.contains(item.root) || table.chains.value(item.root).policy != QLatin1String("-") ||
            table.chains.value(item.root).rules != rootRules) return false;
    }
    return true;
}

bool namespaceAbsent(const Snapshot& snapshot)
{
    for (const SavedTable& table : snapshot.tables) for (const SavedChain& chain : table.chains) {
        if (hasOwnedPrefix(chain.name)) return false;
        for (const QStringList& rule : chain.rules) for (const QString& target : jumpTargets(rule))
            if (hasOwnedPrefix(target)) return false;
    }
    return true;
}

// Validate the exact known table/chain and incoming ownership before changing
// it. No name-prefix adoption and no use of an unsuccessful -C as absence.
bool observedChain(LinuxFirewall::IPVersion ip, const QString& tableName, const QString& chainName, SavedChain* chain)
{
    Snapshot snapshot;
    if (!observeFirewall(ip, &snapshot)) return false;
    for (const OwnedTable& item : safetyTables(ip == LinuxFirewall::IPv6)) {
        if (item.table != tableName) continue;
        QSet<QString> known{item.root};
        for (const QString& anchor : item.anchors) {
            known.insert(kAnchorName + QLatin1Char('.') + anchor);
            known.insert(kAnchorName + QStringLiteral(".a.") + anchor);
        }
        if (!known.contains(chainName) || !snapshot.tables.contains(tableName)) return false;
        const SavedTable table = snapshot.tables.value(tableName);
        TeardownPlan ignored; QString error;
        if (!planTable(table, item, {}, &ignored, &error) || !table.chains.contains(chainName)) return false;
        *chain = table.chains.value(chainName);
        return chain->policy == QLatin1String("-");
    }
    return false;
}

QString renderRule(const QStringList& tokens)
{
    QStringList result;
    for (QString token : tokens) {
        token.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
        token.replace(QLatin1Char('"'), QStringLiteral("\\\""));
        result.append(QLatin1Char('"') + token + QLatin1Char('"'));
    }
    return result.join(QLatin1Char(' '));
}

bool commitTargeted(LinuxFirewall::IPVersion ip, const QString& table, const QStringList& operations)
{
    const TableTransaction transaction{ip == LinuxFirewall::IPv6 ? QStringLiteral("ip6tables-restore") : QStringLiteral("iptables-restore"), table, operations};
    const QByteArray payload = transactionPayload(transaction);
    if (operations.isEmpty() || payload.size() > kMaxSnapshotBytes) return false;
    const ProcessOutcome outcome = runProcess(transaction.program,
        {QStringLiteral("--noflush"), QStringLiteral("--wait=%1").arg(kXtablesLockWaitSeconds)}, payload);
    if (outcome.exitCode != 0 || !outcome.finished || !outcome.terminationComplete || outcome.truncatedErr) {
        logger.error() << "Targeted firewall transaction failed or is uncertain; no rollback attempted:"
                       << transaction.program << table << outcome.exitCode;
        return false;
    }
    return true;
}

bool replaceRules(LinuxFirewall::IPVersion ip, const QString& table, const QString& chain, const QVector<QStringList>& rules)
{
    SavedChain before;
    if (!observedChain(ip, table, chain, &before)) return false;
    if (sameRules(before.rules, rules, ip == LinuxFirewall::IPv6)) return true;
    QStringList operations{QStringLiteral("-F %1").arg(chain)};
    for (const QStringList& rule : rules) operations.append(QStringLiteral("-A %1 %2").arg(chain, renderRule(rule)));
    // Flush and appends share a single COMMIT. A pre-commit refusal preserves
    // old policy. Post-commit observation failure is uncertain, never rollback.
    if (!commitTargeted(ip, table, operations)) return false;
    SavedChain after;
    if (!observedChain(ip, table, chain, &after) || !sameRules(after.rules, rules, ip == LinuxFirewall::IPv6)) {
        logger.error() << "Targeted firewall postcondition not confirmed; state is uncertain:" << table << chain;
        return false;
    }
    return true;
}

bool toggleAnchor(LinuxFirewall::IPVersion ip, const QString& anchor, const QString& table, bool enabled)
{
    const QString placeholder = kAnchorName + QStringLiteral(".a.") + anchor;
    const QString actual = kAnchorName + QLatin1Char('.') + anchor;
    SavedChain link, policy;
    if (!observedChain(ip, table, placeholder, &link) || !observedChain(ip, table, actual, &policy)) return false;
    const QVector<QStringList> on{{QStringLiteral("-j"), actual}};
    if (!link.rules.isEmpty() && link.rules != on) return false;
    return replaceRules(ip, table, placeholder, enabled ? on : QVector<QStringList>{});
}

bool ipv4Network(const QString& input, QString* output)
{
    // Lists are IPv4 netfilter destinations, not shell/restore fragments or
    // DNS names. Canonicalize the prefix so save's network rendering matches.
    for (const QChar c : input) if ((c < QLatin1Char('0') || c > QLatin1Char('9')) && c != QLatin1Char('.') && c != QLatin1Char('/')) return false;
    const QStringList parts = input.split(QLatin1Char('/'));
    if (parts.isEmpty() || parts.size() > 2) return false;
    bool ok = true; uint prefix = 32;
    if (parts.size() == 2) { prefix = parts.at(1).toUInt(&ok); if (!ok || prefix > 32) return false; }
    const QStringList octets = parts.first().split(QLatin1Char('.'));
    if (octets.size() != 4) return false;
    quint32 address = 0;
    for (const QString& octet : octets) {
        const uint n = octet.toUInt(&ok); if (!ok || n > 255) return false;
        address = (address << 8) | n;
    }
    address &= prefix == 0 ? 0u : (0xffffffffu << (32 - prefix));
    *output = QStringLiteral("%1.%2.%3.%4/%5").arg(address >> 24).arg((address >> 16) & 255).arg((address >> 8) & 255).arg(address & 255).arg(prefix);
    return true;
}

// --- Traffic-splitting routing state ----------------------------------------
//
// setupTrafficSplitting()/teardownTrafficSplitting() own exactly two routing
// objects and nothing else:
//   * one policy rule  "from all fwmark 0x3211 lookup amnvpnrt pri 100";
//   * the IPv4 routes in the table named kRtableName (the alias that setup
//     appends to /etc/iproute2/rt_tables).
//
// Teardown therefore has to answer two questions from the tools' own output
// instead of from a shell pipeline, whose exit status folds grep into the
// result and whose pattern matching is substring-based:
//   * does the owned rule exist, and is it unambiguously the rule we add?
//   * does the owned table exist?  A table that the tool proves absent is
//     genuinely nothing to clean, not a failure; anything else that is not a
//     clean success is a real failure and is reported as one.

struct IpObservation
{
    bool observed = false;   // ran to completion, both streams captured
    bool stdoutEmpty = false; // exact byte emptiness, not trimmed-line emptiness
    int exitCode = -2;
    QStringList stdoutLines; // trimmed, non-empty
    QString stderrText;      // trimmed
};

// One bounded, argv-explicit `ip` invocation.  No shell, so the exit status,
// stdout and stderr belong to `ip` alone.
IpObservation observeIp(const QStringList& arguments)
{
    IpObservation observation;
    const ProcessOutcome outcome = runProcess(QStringLiteral("ip"), arguments, {});
    observation.exitCode = outcome.exitCode;
    observation.stdoutEmpty = outcome.out.isEmpty();
    observation.stderrText = QString::fromUtf8(outcome.err).trimmed();
    if (!outcome.started || outcome.writeFailed || outcome.overflowOut || outcome.truncatedErr ||
        !outcome.finished || !outcome.terminationComplete) {
        return observation;
    }
    // print_rule() terminates every text record with a newline.
    if (arguments == QStringList{QStringLiteral("rule"), QStringLiteral("list")} &&
        !outcome.out.isEmpty() && !outcome.out.endsWith('\n')) {
        return observation;
    }
    for (const QString& line : QString::fromUtf8(outcome.out).split(QLatin1Char('\n'))) {
        const QString trimmed = line.trimmed();
        if (!trimmed.isEmpty())
            observation.stdoutLines.append(trimmed);
    }
    observation.observed = true;
    return observation;
}

// The priority setupTrafficSplitting() adds.  A rule that targets our table
// with our mark at any other priority was not created by this firewall.
constexpr quint32 kRulePriority = 100;

struct RuleScan
{
    bool refuse = false;  // ownership cannot be decided; change nothing
    bool owned = false;   // exactly one rule is the rule this firewall adds
    quint32 priority = 0; // observed priority of that rule
    QString reason;
};

// Every `ip rule list` line starts with the rule priority, "N:\t"
// (ip/iprule.c print_rule).  A line that does not is not a rule we can read.
bool rulePriority(const QStringList& tokens, quint32* priority)
{
    if (tokens.isEmpty())
        return false;
    const QString& head = tokens.at(0);
    if (!head.endsWith(QLatin1Char(':')))
        return false;
    bool ok = false;
    const uint value = head.left(head.size() - 1).toUInt(&ok);
    if (!ok)
        return false;
    *priority = value;
    return true;
}

// True only for the exact line `ip rule list` prints for the rule this
// firewall adds.  iproute2 5.15 ip/iprule.c print_rule() emits
//   "100:\tfrom all fwmark 0x3211 lookup amnvpnrt"
// so a masked mark, a different priority, a source selector, any extra
// selector or a different table produces a different token sequence.
bool isExactOwnedRule(const QStringList& tokens, const QString& table, quint32* priority)
{
    quint32 value = 0;
    if (tokens.size() != 7 || !rulePriority(tokens, &value) || value != kRulePriority)
        return false;
    if (tokens.at(1) != QLatin1String("from") || tokens.at(2) != QLatin1String("all"))
        return false;
    if (tokens.at(3) != QLatin1String("fwmark") || tokens.at(4) != kPacketTag)
        return false;
    if (tokens.at(5) != QLatin1String("lookup") || tokens.at(6) != table)
        return false;
    *priority = value;
    return true;
}

// The mark alone, with or without an explicit mask ("0x3211", "0x3211/0xff").
// Token equality is deliberate: 0x32110 is a different mark, even though it
// contains 0x3211 as a substring.
bool carriesOwnedMark(const QStringList& tokens)
{
    for (const QString& token : tokens) {
        if (token == kPacketTag || token.startsWith(kPacketTag + QLatin1Char('/')))
            return true;
    }
    return false;
}

RuleScan scanOwnedRule(const QStringList& lines, const QString& table)
{
    RuleScan scan;
    int matches = 0;
    for (const QString& line : lines) {
        QStringList tokens;
        if (!splitTokens(line, &tokens) || tokens.size() < 2) {
            scan.refuse = true;
            scan.reason = QStringLiteral("cannot parse rule line %1").arg(quoted(line.left(120)));
            return scan;
        }
        quint32 priority = 0;
        if (!rulePriority(tokens, &priority)) {
            scan.refuse = true;
            scan.reason = QStringLiteral("cannot parse rule line %1").arg(quoted(line.left(120)));
            return scan;
        }
        if (isExactOwnedRule(tokens, table, &priority)) {
            ++matches;
            scan.priority = priority;
            continue;
        }
        if (tokens.contains(table) || carriesOwnedMark(tokens)) {
            // A rule that addresses our table or carries our mark but is not
            // byte-for-byte the rule this firewall adds was not created by it.
            // Deleting it, or flushing the table underneath it, would change
            // policy we do not own, so nothing is touched.
            scan.refuse = true;
            scan.reason = QStringLiteral("rule %1 addresses the firewall's mark/table but is "
                                         "not the exact rule this firewall installs")
                              .arg(quoted(line.left(160)));
            return scan;
        }
    }
    if (matches > 1) {
        scan.refuse = true;
        scan.reason = QStringLiteral("the firewall's rule appears %1 times; ownership is "
                                     "ambiguous").arg(matches);
        return scan;
    }
    scan.owned = (matches == 1);
    return scan;
}

// The two failure shapes that mean "the named IPv4 table does not exist",
// derived from iproute2 5.15.0 (the release shipped by Ubuntu 22.04) and the
// kernel it talks to:
//
//   * ip/iproute.c:1929-1930  a table selector with no explicit family narrows
//     the dump to AF_INET, so this command never reports an IPv6 table and the
//     only extack text it can produce is the IPv4 one.
//   * ip/iproute.c:1776-1789  an unresolvable name never reaches the kernel:
//     rtnl_rttable_a2n() fails, invarg() (lib/utils.c:785-789) prints
//     `Error: argument "amnvpnrt" is wrong: table id value is invalid` and
//     exits -1 (255).  No table can exist under a name the tool cannot
//     resolve, so there is nothing of ours to clean.
//   * ip/iproute.c:1704-1706 + lib/libnetlink.c:721-750  a table the kernel
//     does not have: the dump is answered with ENOENT, the extack text is
//     printed as `Error: ipv4: FIB table does not exist.` (kernel
//     net/ipv4/fib_frontend.c:999) and iproute_flush() appends
//     `Flush terminated`, exit -2 (2).  The kernel has no such FIB table, so
//     it holds no route of ours.
//
// Both are full observations: message, exit status and empty stdout must all
// agree.  Anything else - including an ENOENT without the extack text, which
// is what a kernel without extended acks reports - stays a failure.
bool absentTableReported(const IpObservation& flush, const QString& table)
{
    if (!flush.observed || !flush.stdoutEmpty)
        return false;
    if (flush.exitCode == 255) {
        return flush.stderrText ==
               QStringLiteral("Error: argument \"%1\" is wrong: table id value is invalid")
                   .arg(table);
    }
    if (flush.exitCode == 2) {
        return flush.stderrText ==
               QStringLiteral("Error: ipv4: FIB table does not exist.\nFlush terminated");
    }
    return false;
}

}  // namespace




bool LinuxFirewall::install()
{
    Snapshot v4, v6;
    if (!observeFirewall(IPv4, &v4) || !observeFirewall(IPv6, &v6)) return false;
    if (completeFirewall(v4, false) && completeFirewall(v6, true)) {
        // Rebind process-local callbacks without rebuilding kernel policy after
        // a daemon restart. Netfilter completeness does not prove routing.
        anchorCallbacks[enabledKeyTemplate.arg(kMangleTable, QStringLiteral("100.tagPkts"))] = setupTrafficSplitting;
        anchorCallbacks[disabledKeyTemplate.arg(kMangleTable, QStringLiteral("100.tagPkts"))] = teardownTrafficSplitting;
        return setupTrafficSplitting();
    }
    if (!namespaceAbsent(v4) || !namespaceAbsent(v6)) {
        logger.error() << "Partial or unrecognized firewall state; install refused without repair";
        return false;
    }

    // Every stage below records its own failure instead of discarding it.  The
    // remaining stages still run: stopping halfway would leave the firewall in
    // an equally partial state, and the aggregated result is what the caller
    // must act on.
    bool ok = true;
    const auto anchor = [&ok](IPVersion ip, const QString& name, const QStringList& rules) {
        if (!installAnchor(ip, name, rules))
            ok = false;
    };

    // Create a root filter chain to hold all our other anchors in order.
    if (createChain(Both, kRootChain, kFilterTable) != 0)
        ok = false;

    // Create a root raw chain
    if (createChain(Both, kRootChain, kRawTable) != 0)
        ok = false;

    // Create a root NAT chain
    if (createChain(Both, kRootChain, kNatTable) != 0)
        ok = false;

    // Create a root Mangle chain
    if (createChain(Both, kRootChain, kMangleTable) != 0)
        ok = false;

    // Install our filter rulesets in each corresponding anchor chain.
    anchor(Both, QStringLiteral("000.allowLoopback"), {
                                                          QStringLiteral("-o lo+ -j ACCEPT"),
                                                      });

    anchor(IPv4, QStringLiteral("320.allowDNS"), {});

    anchor(Both, QStringLiteral("310.blockDNS"), {
                                                     QStringLiteral("-p udp --dport 53 -j REJECT"),
                                                     QStringLiteral("-p tcp --dport 53 -j REJECT"),
                                                 });
    anchor(IPv4, QStringLiteral("300.allowLAN"), {
                                                     QStringLiteral("-d 10.0.0.0/8 -j ACCEPT"),
                                                     QStringLiteral("-d 169.254.0.0/16 -j ACCEPT"),
                                                     QStringLiteral("-d 172.16.0.0/12 -j ACCEPT"),
                                                     QStringLiteral("-d 192.168.0.0/16 -j ACCEPT"),
                                                     QStringLiteral("-d 224.0.0.0/4 -j ACCEPT"),
                                                     QStringLiteral("-d 255.255.255.255/32 -j ACCEPT"),
                                                 });
    anchor(IPv6, QStringLiteral("300.allowLAN"), {
                                                     QStringLiteral("-d fc00::/7 -j ACCEPT"),
                                                     QStringLiteral("-d fe80::/10 -j ACCEPT"),
                                                     QStringLiteral("-d ff00::/8 -j ACCEPT"),
                                                 });


    anchor(IPv4, QStringLiteral("290.allowDHCP"), {
                                                      QStringLiteral("-p udp -d 255.255.255.255 --sport 68 --dport 67 -j ACCEPT"),
                                                  });
    anchor(IPv6, QStringLiteral("290.allowDHCP"), {
                                                      QStringLiteral("-p udp -d ff00::/8 --sport 546 --dport 547 -j ACCEPT"),
                                                  });
    anchor(IPv6, QStringLiteral("250.blockIPv6"), {
                                                      QStringLiteral("! -o lo+ -j REJECT"),
                                                  });

    anchor(Both, QStringLiteral("200.allowVPN"), {
                                                     QStringLiteral("-o amn0+ -j ACCEPT"),
                                                     QStringLiteral("-o tun0+ -j ACCEPT"),
                                                     QStringLiteral("-o tun2+ -j ACCEPT"),
                                                 });

    anchor(Both, QStringLiteral("130.allowMarkedXray"), {
                                                            QStringLiteral("-m mark --mark %1 -j ACCEPT").arg(amnezia::xray::xrayTrafficMark),
                                                        });

    anchor(IPv4, QStringLiteral("120.blockNets"), {});

    anchor(IPv4, QStringLiteral("110.allowNets"), {});

    anchor(Both, QStringLiteral("400.allowPIA"), {});

    anchor(Both, QStringLiteral("100.blockAll"), {
                                                     QStringLiteral("-j REJECT"),
                                                 });
    // NAT rules
    if (!installAnchor(Both, QStringLiteral("100.transIp"), {

                                                       // Only need the original interface, not the IP.
                                                       // The interface should remain much more stable/unchangeable than the IP
                                                       // (IP can change when changing networks, but interface only changes if adding/removing NICs)
                                                       // this is just a stub rule - the real rule is set at run-time
                                                       // and updates dynamically (via replaceAnchor) when our interface changes
                                                       // it'll take this form: "-o <interface name> -j MASQUERADE"
                                                       QStringLiteral("-j MASQUERADE")
                                                   }, kNatTable))
        ok = false;

    // Mangle rules
    if (!installAnchor(Both, QStringLiteral("100.tagPkts"), {
                                                       QStringLiteral("-m cgroup --cgroup %1 -j MARK --set-mark %2").arg(kCGroupId, kPacketTag)
                                                   }, kMangleTable, setupTrafficSplitting, teardownTrafficSplitting))
        ok = false;

    // A rule to mitigate CVE-2019-14899 - drop packets addressed to the local
    // VPN IP but that are not actually received on the VPN interface.
    // See here: https://seclists.org/oss-sec/2019/q4/122
    if (!installAnchor(Both, QStringLiteral("100.vpnTunOnly"), {
                                                          // To be replaced at runtime
                                                          QStringLiteral("-j ACCEPT")
                                                      }, kRawTable))
        ok = false;


    // Insert our fitler root chain at the top of the OUTPUT chain.
    if (linkChain(Both, kRootChain, kOutputChain, true, kFilterTable) != 0)
        ok = false;

    // Insert our NAT root chain at the top of the POSTROUTING chain.
    if (linkChain(Both, kRootChain, kPostRoutingChain, true, kNatTable) != 0)
        ok = false;

    // Insert our Mangle root chain at the top of the OUTPUT chain.
    if (linkChain(Both, kRootChain, kOutputChain, true, kMangleTable) != 0)
        ok = false;

    // Insert our Raw root chain at the top of the PREROUTING chain.
    if (linkChain(Both, kRootChain, kPreRoutingChain, true, kRawTable) != 0)
        ok = false;

    if (!setupTrafficSplitting())
        ok = false;

    if (!ok || !isInstalled()) {
        logger.error() << "LinuxFirewall::install() finished with failures or an unconfirmed postcondition;"
                       << "the firewall is not fully installed and the caller must not treat it as up";
        return false;
    }
    logger.debug() << "LinuxFirewall::install() complete";
    return true;
}

bool LinuxFirewall::uninstall()
{
    // The exact set of chains and jumps this firewall creates.  Nothing else is
    // ever touched; anything carrying our namespace outside this set aborts the
    // teardown before a single rule is changed.
    const auto ownedTables = [](bool ipv6) {
        QVector<OwnedTable> tables;
        tables.append({kFilterTable, kOutputChain, kRootChain, filterAnchorNames(ipv6)});
        tables.append({kNatTable, kPostRoutingChain, kRootChain,
                       {QStringLiteral("100.transIp")}});
        tables.append({kMangleTable, kOutputChain, kRootChain,
                       {QStringLiteral("100.tagPkts")}});
        tables.append({kRawTable, kPreRoutingChain, kRootChain,
                       {QStringLiteral("100.vpnTunOnly")}});
        return tables;
    };

    const QVector<FamilyPlan> families{
        {QStringLiteral("IPv4"), QStringLiteral("iptables-save"),
         QStringLiteral("iptables-restore"), ownedTables(false)},
        {QStringLiteral("IPv6"), QStringLiteral("ip6tables-save"),
         QStringLiteral("ip6tables-restore"), ownedTables(true)},
    };

    // Plan both families before changing anything so a refusal leaves the
    // firewall exactly as it was.
    TeardownPlan plan;
    QString error;
    for (const FamilyPlan& family : families) {
        if (!planFamily(family, &plan, &error)) {
            logger.error() << "Linux firewall teardown refused before any change:" << error;
            return false;
        }
    }

    bool complete = true;
    for (const TableTransaction& transaction : plan.tables) {
        const QByteArray payload = transactionPayload(transaction);
        if (transaction.operations.isEmpty() || payload.isEmpty()) {
            // iptables-restore with empty stdin exits 0 without committing
            // anything; never let that masquerade as a successful transaction.
            complete = false;
            logger.error() << "Linux firewall transaction was empty; refusing to treat it as committed";
            continue;
        }
        const ProcessOutcome outcome = runProcess(
            transaction.program,
            {QStringLiteral("--noflush"),
             QStringLiteral("--wait=%1").arg(kXtablesLockWaitSeconds)},
            payload);
        if (outcome.exitCode != 0) {
            complete = false;
            if (outcome.writeFailed) {
                logger.error() << "Linux firewall transaction input was not written:"
                               << transaction.program << transaction.table;
            } else if (outcome.overflowOut) {
                logger.error() << "Linux firewall transaction output exceeded the bound:"
                               << transaction.program << transaction.table;
            } else if (!outcome.terminationComplete) {
                logger.error() << "Linux firewall transaction could not be terminated:"
                               << transaction.program << transaction.table;
            } else {
                logger.error() << "Linux firewall transaction failed:"
                               << transaction.program << transaction.table
                               << "exit" << outcome.exitCode
                               << QString::fromUtf8(outcome.err).trimmed();
            }
            // Keep removing what can still be removed; the result still fails.
            continue;
        }
        logger.debug() << "Linux firewall transaction committed:"
                       << transaction.program << transaction.table
                       << transaction.operations.size();
    }

    // The proposal's documented contract is "routing only after every
    // transaction committed".  Do not tear down route ownership while the
    // firewall is only partly removed: a failed transaction is retried, and
    // the retry will perform the routing teardown once it succeeds.
    if (complete) {
        if (!teardownTrafficSplitting())
            complete = false;
    } else {
        logger.error() << "Linux firewall routing teardown skipped because a firewall transaction failed";
    }

    if (!complete) {
        logger.error() << "LinuxFirewall::uninstall() incomplete";
        return false;
    }
    logger.debug() << "LinuxFirewall::uninstall() complete";
    return true;
}

bool LinuxFirewall::isInstalled()
{
    Snapshot v4, v6;
    return observeFirewall(IPv4, &v4) && observeFirewall(IPv6, &v6) &&
           completeFirewall(v4, false) && completeFirewall(v6, true);
}

bool LinuxFirewall::ensureRootAnchorPriority(LinuxFirewall::IPVersion ip)
{
    if (ip == Both) {
        const bool result4 = ensureRootAnchorPriority(IPv4);
        const bool result6 = ensureRootAnchorPriority(IPv6);
        return result4 && result6;
    }
    Snapshot snapshot;
    if (!observeFirewall(ip, &snapshot) || !snapshot.tables.contains(kFilterTable)) return false;
    const SavedTable table = snapshot.tables.value(kFilterTable);
    TeardownPlan ignored; QString error;
    const OwnedTable owned = safetyTables(ip == IPv6).first();
    if (!planTable(table, owned, {}, &ignored, &error) || !table.chains.contains(kRootChain) ||
        !table.chains.contains(kOutputChain)) return false;
    const auto rules = table.chains.value(kOutputChain).rules;
    const QStringList jump{QStringLiteral("-j"), kRootChain};
    const qsizetype index = rules.indexOf(jump);
    if (index == 0) return true;
    // Never rebuild OUTPUT from a snapshot: remove only the exact owned jump
    // and insert it first, leaving every foreign rule in its original order.
    QStringList operations;
    if (index >= 0) operations.append(QStringLiteral("-D %1 -j %2").arg(kOutputChain, kRootChain));
    operations.append(QStringLiteral("-I %1 1 -j %2").arg(kOutputChain, kRootChain));
    if (!commitTargeted(ip, kFilterTable, operations)) return false;
    Snapshot after;
    if (!observeFirewall(ip, &after) || !after.tables.contains(kFilterTable)) return false;
    const SavedTable result = after.tables.value(kFilterTable);
    TeardownPlan postPlan;
    return planTable(result, owned, {}, &postPlan, &error) &&
           result.chains.contains(kOutputChain) &&
           !result.chains.value(kOutputChain).rules.isEmpty() &&
           result.chains.value(kOutputChain).rules.first() == jump;
}

bool LinuxFirewall::enableAnchor(LinuxFirewall::IPVersion ip, const QString &anchor, const QString& tableName)
{
    if (ip == Both) {
        const bool result4 = enableAnchor(IPv4, anchor, tableName);
        const bool result6 = enableAnchor(IPv6, anchor, tableName);
        return result4 && result6;
    }
    return toggleAnchor(ip, anchor, tableName, true);
}

bool LinuxFirewall::replaceAnchor(LinuxFirewall::IPVersion ip, const QString &anchor, const QString &newRule, const QString& tableName)
{
    if (ip == Both) {
        const bool result4 = replaceAnchor(IPv4, anchor, newRule, tableName);
        const bool result6 = replaceAnchor(IPv6, anchor, newRule, tableName);
        return result4 && result6;
    }
    // Only the two runtime-replaced singleton chains are replaceable. Do not
    // let this API silently overwrite an immutable protective chain.
    if (!((tableName == kNatTable && anchor == QLatin1String("100.transIp")) ||
          (tableName == kRawTable && anchor == QLatin1String("100.vpnTunOnly")))) return false;
    for (const QChar c : newRule) if (c.unicode() < 32 || c.unicode() == 127) return false;
    QStringList tokens;
    if (!splitTokens(newRule, &tokens) || tokens.isEmpty()) return false;
    return replaceRules(ip, tableName, kAnchorName + QLatin1Char('.') + anchor, {tokens});
}

bool LinuxFirewall::disableAnchor(LinuxFirewall::IPVersion ip, const QString &anchor, const QString& tableName)
{
    if (ip == Both) {
        const bool result4 = disableAnchor(IPv4, anchor, tableName);
        const bool result6 = disableAnchor(IPv6, anchor, tableName);
        return result4 && result6;
    }
    return toggleAnchor(ip, anchor, tableName, false);
}

bool LinuxFirewall::isAnchorEnabled(LinuxFirewall::IPVersion ip, const QString &anchor, const QString& tableName)
{
    if (ip == Both) return isAnchorEnabled(IPv4, anchor, tableName) && isAnchorEnabled(IPv6, anchor, tableName);
    SavedChain chain;
    return observedChain(ip, tableName, kAnchorName + QStringLiteral(".a.") + anchor, &chain) &&
           chain.rules == QVector<QStringList>{{QStringLiteral("-j"), kAnchorName + QLatin1Char('.') + anchor}};
}

bool LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPVersion ip, const QString &anchor, bool enabled, const QString &tableName)
{
    if (!(enabled ? enableAnchor(ip, anchor, tableName) : disableAnchor(ip, anchor, tableName))) return false;
    const QString key = (enabled ? enabledKeyTemplate : disabledKeyTemplate).arg(tableName, anchor);
    if (anchorCallbacks.contains(key)) return anchorCallbacks.value(key)();
    // A daemon restart loses the callback map, not the kernel policy. Keep
    // routing failures visible even when isInstalled() let a caller skip install.
    if (tableName == kMangleTable && anchor == QLatin1String("100.tagPkts"))
        return enabled ? setupTrafficSplitting() : teardownTrafficSplitting();
    return true;
}

bool LinuxFirewall::updateDNSServers(const QStringList& servers)
{
    QVector<QStringList> rules;
    const QStringList ifaces{QStringLiteral("amn0+"), QStringLiteral("tun0+"), QStringLiteral("tun2+")};
    for (const QString& server : servers) {
        QString address;
        if (!ipv4Network(server, &address) || !address.endsWith(QLatin1String("/32"))) return false;
        for (const QString& iface : ifaces) for (const QString& protocol : {QStringLiteral("udp"), QStringLiteral("tcp")})
            rules.append({QStringLiteral("-o"), iface, QStringLiteral("-d"), address,
                          QStringLiteral("-p"), protocol, QStringLiteral("--dport"), QStringLiteral("53"),
                          QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    }
    return replaceRules(IPv4, kFilterTable, kAnchorName + QStringLiteral(".320.allowDNS"), rules);
}

bool LinuxFirewall::updateAllowNets(const QStringList& servers)
{
    QVector<QStringList> rules;
    for (const QString& server : servers) {
        QString address;
        if (!ipv4Network(server, &address)) return false;
        rules.append({QStringLiteral("-d"), address, QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    }
    return replaceRules(IPv4, kFilterTable, kAnchorName + QStringLiteral(".110.allowNets"), rules);
}

bool LinuxFirewall::updateBlockNets(const QStringList& servers)
{
    QVector<QStringList> rules;
    for (const QString& server : servers) {
        QString address;
        if (!ipv4Network(server, &address)) return false;
        rules.append({QStringLiteral("-d"), address, QStringLiteral("-j"), QStringLiteral("REJECT")});
    }
    return replaceRules(IPv4, kFilterTable, kAnchorName + QStringLiteral(".120.blockNets"), rules);
}

int LinuxFirewall::execute(const QString &command, bool ignoreErrors)
{
    // Same bounded adapter as the teardown transactions: the old path called
    // waitForFinished() with an implicit, unbounded 30 s wait and then read
    // whatever the child had produced, with no bound at all.
    const ProcessOutcome outcome = runProcess(QStringLiteral("/bin/bash"),
                                             {QStringLiteral("-c"), command}, {});
    const int exitCode = outcome.exitCode;
    const QByteArray out = outcome.out.trimmed();
    const QByteArray err = outcome.err.trimmed();
    if ((exitCode != 0 || !err.isEmpty()) && !ignoreErrors)
        logger.warning()  << "(" << exitCode << ") $ " << command;
    if (!out.isEmpty())
        logger.info() << out;
    if (!err.isEmpty())
        logger.warning() << err;
    return exitCode;
}

int LinuxFirewall::executeIptables(const QString &program, const QStringList &args, bool ignoreErrors)
{
    const ProcessOutcome outcome = runProcess(program, args, {});
    const int exitCode = outcome.exitCode;
    const QByteArray out = outcome.out.trimmed();
    const QByteArray err = outcome.err.trimmed();
    if ((exitCode != 0 || !err.isEmpty()) && !ignoreErrors)
        logger.warning() << "(" << exitCode << ") $ " << program << args.join(QLatin1Char(' '));
    if (!out.isEmpty())
        logger.info() << out;
    if (!err.isEmpty())
        logger.warning() << err;
    return exitCode;
}

bool LinuxFirewall::setupTrafficSplitting()
{
    const QString cgroupBase = QStringLiteral("/sys/fs/cgroup/net_cls");
    if (!QFileInfo::exists(cgroupBase)) {
        // A kernel without the net_cls cgroup (e.g. cgroup v2 only) is a
        // supported state: traffic splitting is disabled and the firewall is
        // still fully installed, so this is not an install failure.
        logger.warning() << "net_cls cgroup v1 not available, traffic splitting disabled";
        return true;
    }

    // Use the same exact ownership check for setup and teardown. A foreign
    // mark such as 0x32110 must not suppress installation of our rule, and an
    // unreadable or ambiguous list must stop before configuration is changed.
    const IpObservation rules =
        observeIp({QStringLiteral("rule"), QStringLiteral("list")});
    if (!rules.observed || rules.exitCode != 0) {
        logger.error() << "Traffic-splitting setup could not observe the policy rules";
        return false;
    }
    const RuleScan scan = scanOwnedRule(rules.stdoutLines, kRtableName);
    if (scan.refuse) {
        logger.error() << "Traffic-splitting setup refused before configuration changes:"
                       << scan.reason;
        return false;
    }

    if (execute(QStringLiteral(
        "if ! grep -qE '^[0-9]+[[:space:]]+%1$' /etc/iproute2/rt_tables 2>/dev/null ; then "
        "echo '200 %1' >> /etc/iproute2/rt_tables ; fi"
    ).arg(kRtableName)) != 0)
        return false;

    auto cGroupDir = "/sys/fs/cgroup/net_cls/" BRAND_CODE "vpnexclusions/";
    logger.info() << "Setting up cgroup in" << cGroupDir << "for traffic splitting";
    if (execute(QStringLiteral("if [ ! -d %1 ] ; then mkdir %1 ; sleep 0.1 ; echo %2 > %1/net_cls.classid ; fi").arg(cGroupDir).arg(kCGroupId)) != 0)
        return false;
    if (!scan.owned) {
        const IpObservation added =
            observeIp({QStringLiteral("rule"), QStringLiteral("add"),
                       QStringLiteral("from"), QStringLiteral("all"),
                       QStringLiteral("fwmark"), kPacketTag,
                       QStringLiteral("lookup"), kRtableName,
                       QStringLiteral("pri"), QString::number(kRulePriority)});
        if (!added.observed || added.exitCode != 0) {
            logger.error() << "Traffic-splitting rule installation failed:"
                           << added.exitCode << added.stderrText;
            return false;
        }
    }
    return true;
}

bool LinuxFirewall::teardownTrafficSplitting()
{
    logger.info() << "Tearing down cgroup and routing rules";

    // 1. Read the complete rule list.  This is the only thing that can
    //    establish whether the owned rule exists, and a list that could not be
    //    read (or that contains a rule we cannot attribute) is not "no rule":
    //    in either case nothing is changed.
    const IpObservation rules =
        observeIp({QStringLiteral("rule"), QStringLiteral("list")});
    if (!rules.observed) {
        logger.error() << "ip rule list could not be observed; traffic-splitting state is "
                          "unknown, nothing was changed";
        return false;
    }
    if (rules.exitCode != 0) {
        logger.error() << "ip rule list failed:" << rules.exitCode << rules.stderrText;
        return false;
    }
    const RuleScan scan = scanOwnedRule(rules.stdoutLines, kRtableName);
    if (scan.refuse) {
        logger.error() << "Traffic-splitting teardown refused before any routing change:"
                       << scan.reason;
        return false;
    }

    // 2. Remove exactly the rule that was observed, at the priority that was
    //    observed.  A failed deletion is a real failure and stops the teardown
    //    before the table is flushed under a rule that is still in place.
    if (scan.owned) {
        const IpObservation deleted =
            observeIp({QStringLiteral("rule"), QStringLiteral("del"),
                       QStringLiteral("from"), QStringLiteral("all"),
                       QStringLiteral("fwmark"), kPacketTag,
                       QStringLiteral("lookup"), kRtableName,
                       QStringLiteral("pri"), QString::number(scan.priority)});
        if (!deleted.observed || deleted.exitCode != 0) {
            logger.error() << "ip rule del failed:" << deleted.exitCode << deleted.stderrText;
            return false;
        }
    }

    // 3. Flush the owned table.  A table the tool proves absent (the alias was
    //    never created, or the kernel holds no FIB table for it) is genuinely
    //    nothing to clean - that is the fresh-install case, and it must not
    //    turn into a permanent install failure.  Every other non-zero result
    //    is reported.
    const IpObservation flushed =
        observeIp({QStringLiteral("route"), QStringLiteral("flush"),
                   QStringLiteral("table"), kRtableName});
    if (!flushed.observed) {
        logger.error() << "ip route flush table" << kRtableName
                       << "could not be observed; routing state is unknown";
        return false;
    }
    if (flushed.exitCode != 0 && !absentTableReported(flushed, kRtableName)) {
        logger.error() << "ip route flush table" << kRtableName << "failed:"
                       << flushed.exitCode << flushed.stderrText;
        return false;
    }

    // 4. Drop cached lookups, as before.  Nothing else is touched.
    const IpObservation cache =
        observeIp({QStringLiteral("route"), QStringLiteral("flush"),
                   QStringLiteral("cache")});
    // iproute2 can print a procfs open/write failure but still return zero.
    // A diagnostic-bearing cache flush is not confirmed successful.
    if (!cache.observed || cache.exitCode != 0 || !cache.stderrText.isEmpty()) {
        logger.error() << "ip route flush cache failed:" << cache.exitCode << cache.stderrText;
        return false;
    }
    return true;
}
