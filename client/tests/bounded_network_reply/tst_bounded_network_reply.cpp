#include "../../core/utils/boundedNetworkReply.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <cstdio>
#include <stdexcept>

static void require(bool value, const char *message)
{
    if (!value) throw std::runtime_error(message);
}

static void responseCase(qsizetype bytes, bool bounded, bool length, bool accepted)
{
    QTcpServer server;
    require(server.listen(QHostAddress::LocalHost), "loopback listen failed");
    QObject::connect(&server, &QTcpServer::newConnection, &server, [&]() {
        QTcpSocket *socket = server.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket, [=]() {
            socket->readAll();
            QByteArray response("HTTP/1.1 200 OK\r\nConnection: close\r\n");
            if (length) response += "Content-Length: " + QByteArray::number(bytes) + "\r\n";
            response += "\r\n";
            response += QByteArray(bytes, 'x');
            socket->write(response);
            socket->disconnectFromHost();
        });
    });
    QNetworkAccessManager manager;
    QNetworkReply *reply = manager.get(QNetworkRequest(QUrl(
            QStringLiteral("http://127.0.0.1:%1/").arg(server.serverPort()))));
    auto body = bounded ? amnezia::boundNetworkReplyBody(reply, 4096) : nullptr;
    QEventLoop loop;
    bool timedOut = false;
    QTimer deadline;
    deadline.setSingleShot(true);
    QObject::connect(&deadline, &QTimer::timeout, &loop, [&]() { timedOut = true; loop.quit(); });
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    deadline.start(10000);
    loop.exec();
    require(!timedOut, "response timed out");
    if (!bounded) {
        require(reply->bytesAvailable() == bytes, "legacy response did not buffer full body");
        std::printf("legacy buffered %lld bytes before finished handler\n", static_cast<long long>(reply->bytesAvailable()));
    } else if (accepted) {
        require(!body->tooLarge && body->data.size() == bytes, "valid bounded response rejected");
        require(reply->error() == QNetworkReply::NoError, "valid bounded response network error");
    } else {
        require(body->tooLarge && body->data.isEmpty(), "oversized body not rejected");
        require(reply->error() == QNetworkReply::OperationCanceledError, "oversized response not aborted");
        require(reply->bytesAvailable() <= 4097, "reply buffer exceeded limit");
    }
    reply->deleteLater();
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    try {
        responseCase(8 * 1024 * 1024, false, true, true);
        responseCase(4096, true, true, true);
        responseCase(4096, true, false, true);
        responseCase(4097, true, true, false);
        responseCase(8 * 1024 * 1024, true, false, false);
        std::puts("bounded reply: 5 cases passed");
    } catch (const std::exception &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
    return 0;
}
