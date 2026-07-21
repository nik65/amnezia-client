#ifndef OSSIGNALHANDLER_H
#define OSSIGNALHANDLER_H

#include <QObject>

class OsSignalHandler : public QObject
{
    Q_OBJECT
public:
    static void setup(bool enableConsoleControlHandler = false);
    static int terminationExitCode();

private:
    explicit OsSignalHandler(QObject *parent = nullptr);
    static void handleSignal(int signal);
};

#endif // OSSIGNALHANDLER_H
