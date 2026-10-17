#include <QtTest>

#include <Windows.h>

#include <QByteArray>
#include <QVector>

namespace PipeMock {

struct State {
  QByteArray response;
  QByteArray written;
  QVector<DWORD> readChunks;
  qsizetype responseOffset = 0;
  qsizetype readIndex = 0;
  DWORD maxWrite = 0;
  int closeCount = 0;
  bool failCreate = false;
  bool failWait = false;
  bool failSetMode = false;
  bool failWrite = false;
  bool zeroWrite = false;
  bool zeroRead = false;
  bool failRead = false;
};

State state;

void reset(const QByteArray& response) {
  state = {};
  state.response = response;
}

HANDLE WINAPI createFile(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
                         DWORD, HANDLE) {
  return state.failCreate ? INVALID_HANDLE_VALUE
                          : reinterpret_cast<HANDLE>(0x1234);
}

BOOL WINAPI closeHandle(HANDLE) {
  ++state.closeCount;
  return TRUE;
}
BOOL WINAPI waitNamedPipe(LPCTSTR, DWORD) { return state.failWait ? FALSE : TRUE; }

BOOL WINAPI setNamedPipeHandleState(HANDLE, LPDWORD, LPDWORD, LPDWORD) {
  return state.failSetMode ? FALSE : TRUE;
}

BOOL WINAPI writeFile(HANDLE, LPCVOID data, DWORD requested, LPDWORD written,
                      LPOVERLAPPED) {
  if (state.failWrite) {
    *written = 0;
    return FALSE;
  }
  if (state.zeroWrite) {
    *written = 0;
    return TRUE;
  }
  const DWORD count = state.maxWrite == 0 ? requested
                                           : qMin(requested, state.maxWrite);
  state.written.append(static_cast<const char*>(data), count);
  *written = count;
  return TRUE;
}

BOOL WINAPI readFile(HANDLE, LPVOID data, DWORD requested, LPDWORD read,
                     LPOVERLAPPED) {
  if (state.failRead) {
    *read = 0;
    return FALSE;
  }
  if (state.zeroRead || state.responseOffset >= state.response.size()) {
    *read = 0;
    return TRUE;
  }
  DWORD count = static_cast<DWORD>(state.response.size() - state.responseOffset);
  count = qMin(count, requested);
  if (state.readIndex < state.readChunks.size()) {
    count = qMin(count, state.readChunks[state.readIndex++]);
  }
  memcpy(data, state.response.constData() + state.responseOffset, count);
  state.responseOffset += count;
  *read = count;
  return TRUE;
}

SC_HANDLE WINAPI openScm(LPCTSTR, LPCTSTR, DWORD) {
  return reinterpret_cast<SC_HANDLE>(0x2345);
}

SC_HANDLE WINAPI openService(SC_HANDLE, LPCTSTR, DWORD) { return nullptr; }
BOOL WINAPI closeServiceHandle(SC_HANDLE) { return TRUE; }

}  // namespace PipeMock

#define CreateFile PipeMock::createFile
#define CloseHandle PipeMock::closeHandle
#define WaitNamedPipe PipeMock::waitNamedPipe
#define SetNamedPipeHandleState PipeMock::setNamedPipeHandleState
#define WriteFile PipeMock::writeFile
#define ReadFile PipeMock::readFile
#define OpenSCManager PipeMock::openScm
#define OpenService PipeMock::openService
#define CloseServiceHandle PipeMock::closeServiceHandle
#include "platforms/windows/daemon/windowstunnelservice.cpp"
#undef CreateFile
#undef CloseHandle
#undef WaitNamedPipe
#undef SetNamedPipeHandleState
#undef WriteFile
#undef ReadFile
#undef OpenSCManager
#undef OpenService
#undef CloseServiceHandle

void WindowsUtils::windowsLog(const QString&) {}
QString WindowsUtils::getErrorMessage(quint32) { return QString(); }

WindowsTunnelLogger::WindowsTunnelLogger(std::function<QString(void)> logger,
                                         QObject* parent)
    : QObject(parent) {
  Q_UNUSED(logger);
}
WindowsTunnelLogger::~WindowsTunnelLogger() = default;
void WindowsTunnelLogger::timeout() {}
QString WindowsCommons::tunnelLogFile() { return QString(); }

class UapiTransportTest final : public QObject {
  Q_OBJECT

 private slots:
  void writesCompleteFramedRequestAndReadsSplitResponse() {
    PipeMock::reset("errno=0\n\n");
    PipeMock::state.maxWrite = 1;
    PipeMock::state.readChunks = {2, 1, 3, 99};

    WindowsTunnelService service;
    QCOMPARE(service.uapiCommand(QStringLiteral("set=1")),
             QStringLiteral("errno=0"));
    QCOMPARE(PipeMock::state.written, QByteArray("set=1\n\n"));
    QCOMPARE(PipeMock::state.closeCount, 1);
  }

  void rejectsCreateWaitAndModeFailures() {
    PipeMock::reset("errno=0\n\n");
    PipeMock::state.failCreate = true;
    WindowsTunnelService service;
    QVERIFY(service.uapiCommand(QStringLiteral("get=1")).isEmpty());
    QCOMPARE(PipeMock::state.closeCount, 0);

    PipeMock::reset("errno=0\n\n");
    PipeMock::state.failWait = true;
    QVERIFY(service.uapiCommand(QStringLiteral("get=1")).isEmpty());
    QCOMPARE(PipeMock::state.closeCount, 1);

    PipeMock::reset("errno=0\n\n");
    PipeMock::state.failSetMode = true;
    QVERIFY(service.uapiCommand(QStringLiteral("get=1")).isEmpty());
    QCOMPARE(PipeMock::state.closeCount, 1);
  }

  void rejectsTrailingDataAfterResponseFrame() {
    PipeMock::reset("errno=0\n\njunk");
    WindowsTunnelService service;
    QVERIFY(service.uapiCommand(QStringLiteral("get=1")).isEmpty());
  }

  void rejectsZeroLengthReadAndReadFailure() {
    PipeMock::reset("errno=0\n\n");
    PipeMock::state.zeroRead = true;
    WindowsTunnelService service;
    QVERIFY(service.uapiCommand(QStringLiteral("get=1")).isEmpty());

    PipeMock::reset("errno=0\n\n");
    PipeMock::state.failRead = true;
    QVERIFY(service.uapiCommand(QStringLiteral("get=1")).isEmpty());
  }

  void rejectsZeroWriteAndOversizedFrame() {
    PipeMock::reset("errno=0\n\n");
    PipeMock::state.zeroWrite = true;
    WindowsTunnelService service;
    QVERIFY(service.uapiCommand(QStringLiteral("set=1")).isEmpty());

    PipeMock::reset(QByteArray(64 * 1024 + 1, 'x'));
    QVERIFY(service.uapiCommand(QStringLiteral("get=1")).isEmpty());
  }
};

QTEST_GUILESS_MAIN(UapiTransportTest)
#include "test_uapi_transport.moc"
