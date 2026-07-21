#include <QByteArray>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QList>
#include <QStringList>
#include <QTextStream>

#include "core/utils/remoteLogSanitizer.h"

using namespace amnezia::remoteLogSanitizer;

namespace
{
    class TestRunner
    {
    public:
        void check(bool condition, const char *expression, int line)
        {
            ++m_assertions;
            if (condition) {
                return;
            }
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": " << expression << Qt::endl;
        }

        int finish() const
        {
            QTextStream stream(m_failures == 0 ? stdout : stderr);
            stream << (m_failures == 0 ? "PASS" : "FAIL")
                   << ": " << m_assertions << " assertions, " << m_failures << " failures"
                   << Qt::endl;
            return m_failures == 0 ? 0 : 1;
        }

    private:
        int m_assertions = 0;
        int m_failures = 0;
    };

    ChunkContext chunkContext(bool startsInsideRecord, bool endsInsideRecord,
                              bool privateKeyBlockOpen,
                              qsizetype privateKeyEndMarkerCharacters = 0)
    {
        ChunkContext context;
        context.startsInsideRecord = startsInsideRecord;
        context.endsInsideRecord = endsInsideRecord;
        context.privateKeyBlockOpen = privateKeyBlockOpen;
        context.privateKeyEndMarkerCharacters = privateKeyEndMarkerCharacters;
        return context;
    }
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    TestRunner runner;

    const QString exactBootstrapToken = QStringLiteral("BOOTSTRAP-TOKEN-8f398d8fc17b");
    const QString installationUuid = QStringLiteral("123e4567-e89b-12d3-a456-426614174000");
    const QByteArray corpus = QByteArrayLiteral(
            "route add 10.0.0.0/8 via vpn.example.com metric=50\n"
            "health=degraded latency_ms=125 endpoint=198.51.100.7:443\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret.signature\n"
            "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\n"
            "payload={\"password\":\"correct horse battery staple\",\"token\":\"json-token-123\"}\n"
            "xray={\"user\":\"client\",\"pass\":\"xray-pass-secret\"}\n"
            "mtproxy_additional_secrets=[\"mt-secret-one\",\"mt-secret-two\"]\n"
            "telemt_additional_secrets: [\n\"telemt-secret-one\",\n\"telemt-secret-two\"\n]\n"
            "password: unquoted secret with spaces\n"
            "client_secret=top-secret-value api_key:abc123456789\n"
            "server_priv_key=SERVER-WG-PRIVATE-KEY\n"
            "mtproxy_secret=MT-PROXY-SECRET\n"
            "telemt_secret: TELEMT-SECRET\n"
            "aes_key=AES-KEY-MATERIAL aes_iv=AES-IV-MATERIAL aes_salt=AES-SALT-MATERIAL\n"
            "vpn_key=VPN-SUBSCRIPTION-KEY tls_auth=OPENVPN-STATIC-KEY\n"
            "PrivateKey = WG-PRIVATE-KEY-BASE64=\n"
            "PresharedKey=WG-PSK-BASE64=\n"
            "request=https://alice:hunter2@example.net/api/v1/health?token=url-secret-123&mode=full\n"
            "Cookie: session=browser-session-secret; theme=dark\n"
            "X-Amnezia-Installation-Id: 123e4567-e89b-12d3-a456-426614174000\n"
            "bootstrap value BOOTSTRAP-TOKEN-8f398d8fc17b\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAAprivate-body\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
            "route keep 2001:db8::/32 via healthy.example.org\n");

    const SanitizedChunk sanitized = sanitize(corpus, {}, { exactBootstrapToken, installationUuid });
    CHECK(!sanitized.privateKeyBlockOpen);
    const QString output = QString::fromUtf8(sanitized.data);
    const QStringList forbidden {
        QStringLiteral("eyJhbGciOiJIUzI1NiJ9.secret.signature"),
        QStringLiteral("dXNlcjpwYXNzd29yZA=="),
        QStringLiteral("correct horse battery staple"),
        QStringLiteral("unquoted secret with spaces"),
        QStringLiteral("json-token-123"),
        QStringLiteral("xray-pass-secret"),
        QStringLiteral("mt-secret-one"),
        QStringLiteral("mt-secret-two"),
        QStringLiteral("telemt-secret-one"),
        QStringLiteral("telemt-secret-two"),
        QStringLiteral("top-secret-value"),
        QStringLiteral("abc123456789"),
        QStringLiteral("SERVER-WG-PRIVATE-KEY"),
        QStringLiteral("MT-PROXY-SECRET"),
        QStringLiteral("TELEMT-SECRET"),
        QStringLiteral("AES-KEY-MATERIAL"),
        QStringLiteral("AES-IV-MATERIAL"),
        QStringLiteral("AES-SALT-MATERIAL"),
        QStringLiteral("VPN-SUBSCRIPTION-KEY"),
        QStringLiteral("OPENVPN-STATIC-KEY"),
        QStringLiteral("WG-PRIVATE-KEY-BASE64="),
        QStringLiteral("WG-PSK-BASE64="),
        QStringLiteral("alice:hunter2"),
        QStringLiteral("url-secret-123"),
        QStringLiteral("browser-session-secret"),
        installationUuid,
        exactBootstrapToken,
        QStringLiteral("b3BlbnNzaC1rZXktdjEAAAAAprivate-body")
    };
    for (const QString &secret : forbidden) {
        CHECK(!output.contains(secret));
    }
    CHECK(output.contains(QStringLiteral("route add 10.0.0.0/8 via vpn.example.com metric=50")));
    CHECK(output.contains(QStringLiteral("health=degraded latency_ms=125 endpoint=198.51.100.7:443")));
    CHECK(output.contains(QStringLiteral("route keep 2001:db8::/32 via healthy.example.org")));
    CHECK(output.contains(QStringLiteral("[REDACTED PRIVATE KEY]")));

    const QByteArray firstPemChunk = QByteArrayLiteral(
            "ok before key\n-----BEGIN RSA PRIVATE KEY-----\nfirst-private-line\n");
    const SanitizedChunk firstPem = sanitize(firstPemChunk);
    CHECK(firstPem.privateKeyBlockOpen);
    CHECK(!firstPem.data.contains("first-private-line"));
    const QByteArray secondPemChunk = QByteArrayLiteral(
            "second-private-line\n-----END RSA PRIVATE KEY-----\nhealth=healthy route=10.1.0.0/16\n");
    const SanitizedChunk secondPem = sanitize(
            secondPemChunk, chunkContext(false, false, firstPem.privateKeyBlockOpen));
    CHECK(!secondPem.privateKeyBlockOpen);
    CHECK(!secondPem.data.contains("second-private-line"));
    CHECK(secondPem.data.contains("health=healthy route=10.1.0.0/16"));

    CHECK(privateKeyBlockOpenAtEnd(firstPemChunk));
    CHECK(!privateKeyBlockOpenAtEnd(secondPemChunk, true));

    const QByteArray splitBeginLeft = QByteArrayLiteral(
            "health=healthy\n-----BEGIN OPENSSH PRIV");
    const SanitizedChunk splitBeginLeftSanitized = sanitize(
            splitBeginLeft, chunkContext(false, true, false));
    CHECK(!splitBeginLeftSanitized.data.contains("OPENSSH PRIV"));
    const QByteArray splitBeginRight = QByteArrayLiteral(
            "ATE KEY-----\nprivate-across-boundary\n-----END OPENSSH PRIVATE KEY-----\n"
            "route=10.2.0.0/16 health=healthy\n");
    const PrivateKeyBoundary splitBeginBoundary = inspectPrivateKeyBoundary(
            splitBeginLeft, splitBeginRight);
    CHECK(splitBeginBoundary.beginMarkerCrossesBoundary);
    const SanitizedChunk splitBeginSanitized = sanitize(
            splitBeginRight,
            chunkContext(true, false, splitBeginBoundary.beginMarkerCrossesBoundary));
    CHECK(!splitBeginSanitized.privateKeyBlockOpen);
    CHECK(!splitBeginSanitized.data.contains("private-across-boundary"));
    CHECK(splitBeginSanitized.data.contains("route=10.2.0.0/16 health=healthy"));

    const QByteArray splitEndLeft = QByteArrayLiteral(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-before-split-end\n"
            "-----END OPENSSH PRIV");
    const SanitizedChunk splitEndLeftSanitized = sanitize(
            splitEndLeft, chunkContext(false, true, false));
    CHECK(splitEndLeftSanitized.privateKeyBlockOpen);
    CHECK(!splitEndLeftSanitized.data.contains("private-before-split-end"));
    const QByteArray splitEndRight = QByteArrayLiteral(
            "ATE KEY-----\nhealth=healthy route=10.3.0.0/16\n");
    const PrivateKeyBoundary splitEndBoundary = inspectPrivateKeyBoundary(
            splitEndLeft, splitEndRight);
    CHECK(splitEndBoundary.endMarkerCharactersInInput > 0);
    const SanitizedChunk splitEndSanitized = sanitize(
            splitEndRight,
            chunkContext(true, false, true,
                         splitEndBoundary.endMarkerCharactersInInput));
    CHECK(!splitEndSanitized.privateKeyBlockOpen);
    CHECK(splitEndSanitized.data.contains("health=healthy route=10.3.0.0/16"));

    const QByteArray earlierCompletePemThenSplitBegin = QByteArrayLiteral(
            "-----BEGIN PRIVATE KEY-----\nold-private\n-----END PRIVATE KEY-----\n"
            "health=healthy\n-----BEGIN OPENSSH PRIV");
    const PrivateKeyBoundary secondSplitBeginBoundary = inspectPrivateKeyBoundary(
            earlierCompletePemThenSplitBegin, splitBeginRight);
    CHECK(secondSplitBeginBoundary.beginMarkerCrossesBoundary);
    const SanitizedChunk secondSplitBeginSanitized = sanitize(
            splitBeginRight,
            chunkContext(true, false, secondSplitBeginBoundary.beginMarkerCrossesBoundary));
    CHECK(!secondSplitBeginSanitized.data.contains("private-across-boundary"));
    CHECK(secondSplitBeginSanitized.data.contains("route=10.2.0.0/16 health=healthy"));

    QByteArray longOpenPrivateKey = QByteArrayLiteral("-----BEGIN PRIVATE KEY-----\n");
    while (longOpenPrivateKey.size() < MaximumPrivateKeyLookbehindBytes + 4096) {
        longOpenPrivateKey.append("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n");
    }
    CHECK(privateKeyBlockOpenAtEnd(longOpenPrivateKey));
    const SanitizedChunk longPemTail = sanitize(
            QByteArrayLiteral("still-private-after-one-megabyte\n-----END PRIVATE KEY-----\nhealth=healthy\n"),
            chunkContext(false, false, privateKeyBlockOpenAtEnd(longOpenPrivateKey)));
    CHECK(!longPemTail.data.contains("still-private-after-one-megabyte"));
    CHECK(longPemTail.data.contains("health=healthy"));

    QByteArray internallySplitMarker(MaximumPrivateKeyLookbehindBytes - 12, 'x');
    internallySplitMarker.append("-----BEGIN PRIVATE KEY-----\nprivate\n");
    CHECK(privateKeyBlockOpenAtEnd(internallySplitMarker));

    QByteArray longSecretArray = QByteArrayLiteral("mtproxy_additional_secrets=[\"");
    longSecretArray.append(QByteArray(64 * 1024, 's'));
    longSecretArray.append("\"]\nhealth=healthy\n");
    const SanitizedChunk longArraySanitized = sanitize(longSecretArray);
    CHECK(!longArraySanitized.data.contains(QByteArray(128, 's')));
    CHECK(longArraySanitized.data.contains("health=healthy"));

    const SanitizedChunk unterminatedArraySanitized = sanitize(QByteArrayLiteral(
            "health=degraded\ntelemt_additional_secrets=[\n\"must-not-leak\"\n"
            "route-after-malformed-array=10.4.0.0/16\n"));
    CHECK(!unterminatedArraySanitized.data.contains("must-not-leak"));
    CHECK(!unterminatedArraySanitized.data.contains("route-after-malformed-array"));

    const SanitizedChunk prettyPrintedSecrets = sanitize(QByteArrayLiteral(
            "{\n  \"password\"\n  :\n  \"pretty-password-secret\",\n"
            "  \"mtproxy_additional_secrets\"\n  :\n"
            "  [\"pretty-array-secret\"]\n}\nhealth=healthy\n"));
    CHECK(!prettyPrintedSecrets.data.contains("pretty-password-secret"));
    CHECK(!prettyPrintedSecrets.data.contains("pretty-array-secret"));
    CHECK(prettyPrintedSecrets.data.contains("health=healthy"));

    const SanitizedChunk scalarKeyChunk = sanitize(QByteArrayLiteral(
            "\"server_priv_key\":\n"));
    CHECK(scalarKeyChunk.streamState.pendingSecretKind == PendingSecretKind::Scalar);
    CHECK(scalarKeyChunk.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingValue);
    ChunkContext scalarContinuationContext;
    scalarContinuationContext.streamState = scalarKeyChunk.streamState;
    const SanitizedChunk scalarContinuation = sanitize(QByteArrayLiteral(
            "\"cross-chunk-scalar-secret\"\nhealth=after-scalar\n"),
            scalarContinuationContext);
    CHECK(!scalarContinuation.data.contains("cross-chunk-scalar-secret"));
    CHECK(scalarContinuation.data.contains("health=after-scalar"));
    CHECK(scalarContinuation.streamState.pendingSecretKind == PendingSecretKind::None);
    CHECK(scalarContinuation.streamState.pendingSecretPhase == PendingSecretPhase::None);

    const SanitizedChunk keyOnlyChunk = sanitize(QByteArrayLiteral("\"password\"\n"));
    CHECK(keyOnlyChunk.streamState.pendingSecretKind == PendingSecretKind::Scalar);
    CHECK(keyOnlyChunk.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    ChunkContext keyOnlyContinuationContext;
    keyOnlyContinuationContext.streamState = keyOnlyChunk.streamState;
    const SanitizedChunk keyOnlyContinuation = sanitize(QByteArrayLiteral(
            "\"key-only-next-line-secret\"\nhealth=after-key-only\n"),
            keyOnlyContinuationContext);
    CHECK(!keyOnlyContinuation.data.contains("key-only-next-line-secret"));
    CHECK(keyOnlyContinuation.data.contains("health=after-key-only"));
    CHECK(keyOnlyContinuation.streamState.pendingSecretPhase == PendingSecretPhase::None);

    const QByteArray parenthesizedScalarPrefix = QByteArrayLiteral(
            "health=before-parenthesized-scalar\npayload=(\"password\"");
    const QByteArray parenthesizedScalarSuffix = QByteArrayLiteral(
            ":\n\"LEAK-parenthesized-scalar-secret\"\n"
            "health=after-parenthesized-scalar\n");
    const SanitizedChunk parenthesizedScalarKey = sanitize(
            parenthesizedScalarPrefix);
    CHECK(parenthesizedScalarKey.streamState.pendingSecretKind
          == PendingSecretKind::Scalar);
    CHECK(parenthesizedScalarKey.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    ChunkContext parenthesizedScalarContext;
    parenthesizedScalarContext.streamState = parenthesizedScalarKey.streamState;
    const SanitizedChunk parenthesizedScalarContinuation = sanitize(
            parenthesizedScalarSuffix, parenthesizedScalarContext);
    CHECK(!parenthesizedScalarContinuation.data.contains(
            "LEAK-parenthesized-scalar-secret"));
    CHECK(parenthesizedScalarContinuation.data.contains(
            "health=after-parenthesized-scalar"));

    // A first upload reconstructs stream state up to initialOffset before it
    // sanitizes the tail. Exercise that same state-scan + boundary path with
    // the offset exactly after the parenthesized key.
    const StreamState parenthesizedInitialOffsetState = advanceStreamState(
            {}, parenthesizedScalarPrefix);
    const StreamBoundary parenthesizedInitialOffsetBoundary = inspectStreamBoundary(
            parenthesizedScalarPrefix.right(MaximumPrivateKeyMarkerBytes),
            parenthesizedScalarSuffix,
            parenthesizedInitialOffsetState);
    ChunkContext parenthesizedInitialOffsetContext;
    parenthesizedInitialOffsetContext.startsInsideRecord = true;
    parenthesizedInitialOffsetContext.streamState = parenthesizedInitialOffsetState;
    parenthesizedInitialOffsetContext.boundaryBlockKind =
            parenthesizedInitialOffsetBoundary.beginBlockKind;
    parenthesizedInitialOffsetContext.secretBlockEndMarkerCharacters =
            parenthesizedInitialOffsetBoundary.endBlockMarkerCharactersInInput;
    parenthesizedInitialOffsetContext.secretArrayStartCharacters =
            parenthesizedInitialOffsetBoundary.secretArrayStartCharactersInInput;
    parenthesizedInitialOffsetContext.boundaryPendingSecretKind =
            parenthesizedInitialOffsetBoundary.pendingSecretKind;
    parenthesizedInitialOffsetContext.boundaryPendingSecretPhase =
            parenthesizedInitialOffsetBoundary.pendingSecretPhase;
    parenthesizedInitialOffsetContext.boundaryPendingSecretCharacters =
            parenthesizedInitialOffsetBoundary.pendingSecretCharactersInInput;
    parenthesizedInitialOffsetContext.boundaryPendingSecretWhitespaceBytes =
            parenthesizedInitialOffsetBoundary.pendingSecretWhitespaceBytes;
    const SanitizedChunk parenthesizedInitialOffsetContinuation = sanitize(
            parenthesizedScalarSuffix, parenthesizedInitialOffsetContext);
    CHECK(parenthesizedInitialOffsetState.pendingSecretKind
          == PendingSecretKind::Scalar);
    CHECK(parenthesizedInitialOffsetState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(!parenthesizedInitialOffsetContinuation.data.contains(
            "LEAK-parenthesized-scalar-secret"));
    CHECK(parenthesizedInitialOffsetContinuation.data.contains(
            "health=after-parenthesized-scalar"));

    const QByteArray scalarDelimiterSecret = QByteArrayLiteral(
            "scalar-delimiter-boundary-secret");
    const QByteArray arrayDelimiterSecret = QByteArrayLiteral(
            "array-delimiter-boundary-secret");
    const QList<QByteArray> keyBoundaryPrefixes {
        {},
        QByteArrayLiteral("prefix "),
        QByteArrayLiteral("prefix\t"),
        QByteArrayLiteral("prefix{"),
        QByteArrayLiteral("prefix["),
        QByteArrayLiteral("prefix,"),
        QByteArrayLiteral("health=before-lf-control\n"),
        QByteArrayLiteral("health=before-crlf-control\r\n"),
        QByteArrayLiteral("prefix("),
        QByteArrayLiteral("prefix."),
        QByteArrayLiteral("prefix;"),
        QByteArrayLiteral("prefix)"),
        QByteArrayLiteral("prefix="),
        QByteArrayLiteral("prefix:"),
        QByteArrayLiteral("prefix?"),
        QByteArrayLiteral("prefix&"),
        QByteArrayLiteral("prefix/"),
        QByteArrayLiteral("prefix]"),
        QByteArrayLiteral("prefix}"),
        QByteArrayLiteral("prefix\\")
    };
    const QList<QByteArray> scalarBoundaryLineBreaks {
        QByteArrayLiteral("\n"),
        QByteArrayLiteral("\r\n")
    };
    for (const QByteArray &keyBoundaryPrefix : keyBoundaryPrefixes) {
        for (const QByteArray &lineBreak : scalarBoundaryLineBreaks) {
            for (const bool quoted : { false, true }) {
                QByteArray scalarDelimiterPrefix = keyBoundaryPrefix;
                scalarDelimiterPrefix.append(quoted ? QByteArrayLiteral("\"password\"")
                                                    : QByteArrayLiteral("password"));
                QByteArray scalarDelimiterSuffix = QByteArrayLiteral(":");
                scalarDelimiterSuffix.append(lineBreak);
                scalarDelimiterSuffix.append('"');
                scalarDelimiterSuffix.append(scalarDelimiterSecret);
                scalarDelimiterSuffix.append('"');
                scalarDelimiterSuffix.append(lineBreak);
                scalarDelimiterSuffix.append(
                        QByteArrayLiteral("health=after-scalar-delimiter\n"));
                CHECK(!sanitize(scalarDelimiterPrefix + scalarDelimiterSuffix)
                               .data.contains(scalarDelimiterSecret));
                const SanitizedChunk scalarDelimiterKey = sanitize(scalarDelimiterPrefix);
                CHECK(scalarDelimiterKey.streamState.pendingSecretKind
                      == PendingSecretKind::Scalar);
                CHECK(scalarDelimiterKey.streamState.pendingSecretPhase
                      == PendingSecretPhase::AwaitingSeparator);
                ChunkContext scalarDelimiterContext;
                scalarDelimiterContext.streamState = scalarDelimiterKey.streamState;
                const SanitizedChunk scalarDelimiterContinuation = sanitize(
                        scalarDelimiterSuffix, scalarDelimiterContext);
                CHECK(!scalarDelimiterContinuation.data.contains(scalarDelimiterSecret));
                CHECK(scalarDelimiterContinuation.data.contains(
                        "health=after-scalar-delimiter"));

                const StreamState scalarInitialOffsetState = advanceStreamState(
                        {}, scalarDelimiterPrefix);
                CHECK(scalarInitialOffsetState.pendingSecretKind
                      == PendingSecretKind::Scalar);
                CHECK(scalarInitialOffsetState.pendingSecretPhase
                      == PendingSecretPhase::AwaitingSeparator);
                const StreamBoundary scalarInitialOffsetBoundary = inspectStreamBoundary(
                        scalarDelimiterPrefix.right(MaximumPrivateKeyMarkerBytes),
                        scalarDelimiterSuffix,
                        scalarInitialOffsetState);
                ChunkContext scalarInitialOffsetContext;
                scalarInitialOffsetContext.startsInsideRecord = true;
                scalarInitialOffsetContext.streamState = scalarInitialOffsetState;
                scalarInitialOffsetContext.boundaryPendingSecretKind =
                        scalarInitialOffsetBoundary.pendingSecretKind;
                scalarInitialOffsetContext.boundaryPendingSecretPhase =
                        scalarInitialOffsetBoundary.pendingSecretPhase;
                scalarInitialOffsetContext.boundaryPendingSecretCharacters =
                        scalarInitialOffsetBoundary.pendingSecretCharactersInInput;
                scalarInitialOffsetContext.boundaryPendingSecretWhitespaceBytes =
                        scalarInitialOffsetBoundary.pendingSecretWhitespaceBytes;
                const SanitizedChunk scalarInitialOffsetContinuation = sanitize(
                        scalarDelimiterSuffix, scalarInitialOffsetContext);
                CHECK(!scalarInitialOffsetContinuation.data.contains(
                        scalarDelimiterSecret));
                CHECK(scalarInitialOffsetContinuation.data.contains(
                        "health=after-scalar-delimiter"));

                QByteArray arrayDelimiterPrefix = keyBoundaryPrefix;
                arrayDelimiterPrefix.append(
                        quoted ? QByteArrayLiteral("\"additional_secrets\"")
                               : QByteArrayLiteral("additional_secrets"));
                QByteArray arrayDelimiterSuffix = QByteArrayLiteral(":");
                arrayDelimiterSuffix.append(lineBreak);
                arrayDelimiterSuffix.append(QByteArrayLiteral("[\""));
                arrayDelimiterSuffix.append(arrayDelimiterSecret);
                arrayDelimiterSuffix.append(QByteArrayLiteral("\"]"));
                arrayDelimiterSuffix.append(lineBreak);
                arrayDelimiterSuffix.append(
                        QByteArrayLiteral("health=after-array-delimiter\n"));
                CHECK(!sanitize(arrayDelimiterPrefix + arrayDelimiterSuffix)
                               .data.contains(arrayDelimiterSecret));
                const SanitizedChunk arrayDelimiterKey = sanitize(arrayDelimiterPrefix);
                CHECK(arrayDelimiterKey.streamState.pendingSecretKind
                      == PendingSecretKind::Array);
                CHECK(arrayDelimiterKey.streamState.pendingSecretPhase
                      == PendingSecretPhase::AwaitingSeparator);
                ChunkContext arrayDelimiterContext;
                arrayDelimiterContext.streamState = arrayDelimiterKey.streamState;
                const SanitizedChunk arrayDelimiterContinuation = sanitize(
                        arrayDelimiterSuffix, arrayDelimiterContext);
                CHECK(!arrayDelimiterContinuation.data.contains(arrayDelimiterSecret));
                CHECK(arrayDelimiterContinuation.data.contains(
                        "health=after-array-delimiter"));

                const StreamState arrayInitialOffsetState = advanceStreamState(
                        {}, arrayDelimiterPrefix);
                CHECK(arrayInitialOffsetState.pendingSecretKind
                      == PendingSecretKind::Array);
                CHECK(arrayInitialOffsetState.pendingSecretPhase
                      == PendingSecretPhase::AwaitingSeparator);
                const StreamBoundary arrayInitialOffsetBoundary = inspectStreamBoundary(
                        arrayDelimiterPrefix.right(MaximumPrivateKeyMarkerBytes),
                        arrayDelimiterSuffix,
                        arrayInitialOffsetState);
                ChunkContext arrayInitialOffsetContext;
                arrayInitialOffsetContext.startsInsideRecord = true;
                arrayInitialOffsetContext.streamState = arrayInitialOffsetState;
                arrayInitialOffsetContext.boundaryPendingSecretKind =
                        arrayInitialOffsetBoundary.pendingSecretKind;
                arrayInitialOffsetContext.boundaryPendingSecretPhase =
                        arrayInitialOffsetBoundary.pendingSecretPhase;
                arrayInitialOffsetContext.boundaryPendingSecretCharacters =
                        arrayInitialOffsetBoundary.pendingSecretCharactersInInput;
                arrayInitialOffsetContext.boundaryPendingSecretWhitespaceBytes =
                        arrayInitialOffsetBoundary.pendingSecretWhitespaceBytes;
                const SanitizedChunk arrayInitialOffsetContinuation = sanitize(
                        arrayDelimiterSuffix, arrayInitialOffsetContext);
                CHECK(!arrayInitialOffsetContinuation.data.contains(
                        arrayDelimiterSecret));
                CHECK(arrayInitialOffsetContinuation.data.contains(
                        "health=after-array-delimiter"));
            }
        }
    }

    const auto serializedQuote = [](qsizetype backslashCount) {
        QByteArray quote(backslashCount, '\\');
        quote.append('"');
        return quote;
    };
    const QByteArray escapedScalarSecret = QByteArrayLiteral(
            "escaped-json-scalar-secret");
    const QByteArray escapedArraySecret = QByteArrayLiteral(
            "escaped-json-array-secret");
    for (const qsizetype backslashCount : {
                 qsizetype(1), qsizetype(2), qsizetype(3), qsizetype(7),
                 qsizetype(65), qsizetype(127), qsizetype(1024),
                 qsizetype(65536) }) {
        const QByteArray quote = serializedQuote(backslashCount);
        QByteArray escapedScalar = QByteArrayLiteral("payload={");
        escapedScalar.append(quote);
        escapedScalar.append(QByteArrayLiteral("password"));
        escapedScalar.append(quote);
        escapedScalar.append(':');
        escapedScalar.append(quote);
        escapedScalar.append(escapedScalarSecret);
        escapedScalar.append(quote);
        escapedScalar.append(QByteArrayLiteral("}\nhealth=after-escaped-scalar\n"));
        const SanitizedChunk escapedScalarSanitized = sanitize(escapedScalar);
        CHECK(!escapedScalarSanitized.data.contains(escapedScalarSecret));
        CHECK(escapedScalarSanitized.data.contains("health=after-escaped-scalar"));

        QByteArray escapedArray = QByteArrayLiteral("payload={");
        escapedArray.append(quote);
        escapedArray.append(QByteArrayLiteral("additional_secrets"));
        escapedArray.append(quote);
        escapedArray.append(QByteArrayLiteral(":["));
        escapedArray.append(quote);
        escapedArray.append(escapedArraySecret);
        escapedArray.append(quote);
        escapedArray.append(QByteArrayLiteral("]}\nhealth=after-escaped-array\n"));
        const SanitizedChunk escapedArraySanitized = sanitize(escapedArray);
        CHECK(!escapedArraySanitized.data.contains(escapedArraySecret));
        CHECK(escapedArraySanitized.streamState.pendingSecretKind
              == PendingSecretKind::Array);
        CHECK(escapedArraySanitized.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
    }

    for (const qsizetype structuralBackslashes : {
                 qsizetype(1), qsizetype(3), qsizetype(7) }) {
        const QByteArray structuralQuote = serializedQuote(structuralBackslashes);
        const QByteArray embeddedQuote = serializedQuote(
                2 * structuralBackslashes + 1);
        QByteArray escapedArrayWithEmbeddedBracket = QByteArrayLiteral("payload={");
        escapedArrayWithEmbeddedBracket.append(structuralQuote);
        escapedArrayWithEmbeddedBracket.append(
                QByteArrayLiteral("additional_secrets"));
        escapedArrayWithEmbeddedBracket.append(structuralQuote);
        escapedArrayWithEmbeddedBracket.append(QByteArrayLiteral(":["));
        escapedArrayWithEmbeddedBracket.append(structuralQuote);
        escapedArrayWithEmbeddedBracket.append(QByteArrayLiteral("FIRST"));
        escapedArrayWithEmbeddedBracket.append(embeddedQuote);
        escapedArrayWithEmbeddedBracket.append(
                QByteArrayLiteral("]LEAK-IN-ELEMENT"));
        escapedArrayWithEmbeddedBracket.append(structuralQuote);
        escapedArrayWithEmbeddedBracket.append(',');
        escapedArrayWithEmbeddedBracket.append(structuralQuote);
        escapedArrayWithEmbeddedBracket.append(
                QByteArrayLiteral("SECOND-ESCAPED-ARRAY-SECRET"));
        escapedArrayWithEmbeddedBracket.append(structuralQuote);
        escapedArrayWithEmbeddedBracket.append(
                QByteArrayLiteral("]}\nhealth=after-embedded-bracket-array\n"));
        const SanitizedChunk escapedArrayWithEmbeddedBracketSanitized = sanitize(
                escapedArrayWithEmbeddedBracket);
        CHECK(!escapedArrayWithEmbeddedBracketSanitized.data.contains(
                "LEAK-IN-ELEMENT"));
        CHECK(!escapedArrayWithEmbeddedBracketSanitized.data.contains(
                "SECOND-ESCAPED-ARRAY-SECRET"));
        CHECK(escapedArrayWithEmbeddedBracketSanitized.streamState.pendingSecretKind
              == PendingSecretKind::Array);
        CHECK(escapedArrayWithEmbeddedBracketSanitized.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
    }

    for (const qsizetype structuralBackslashes : {
                 qsizetype(1), qsizetype(2), qsizetype(3), qsizetype(7) }) {
        const QByteArray quote = serializedQuote(structuralBackslashes);
        QByteArray escapedMultilineScalar = QByteArrayLiteral(
                "health=before-multiline-scalar\r\npayload={");
        escapedMultilineScalar.append(quote);
        escapedMultilineScalar.append(QByteArrayLiteral("password"));
        escapedMultilineScalar.append(quote);
        escapedMultilineScalar.append(QByteArrayLiteral(":\r\n"));
        escapedMultilineScalar.append(quote);
        escapedMultilineScalar.append(
                QByteArrayLiteral("MULTILINE-SCALAR-SECRET"));
        escapedMultilineScalar.append(quote);
        escapedMultilineScalar.append(
                QByteArrayLiteral("\r\n}\r\nhealth=after-multiline-scalar\r\n"));
        const SanitizedChunk escapedMultilineScalarSanitized = sanitize(
                escapedMultilineScalar);
        CHECK(!escapedMultilineScalarSanitized.data.contains(
                "MULTILINE-SCALAR-SECRET"));
        CHECK(escapedMultilineScalarSanitized.data.contains(
                "health=after-multiline-scalar"));

        QByteArray escapedMultilineArray = QByteArrayLiteral(
                "health=before-multiline-array\r\npayload={");
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(QByteArrayLiteral("additional_secrets"));
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(QByteArrayLiteral(":\r\n[\r\n"));
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(QByteArrayLiteral("FIRST-MULTILINE-SECRET"));
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(QByteArrayLiteral(",\r\n"));
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(QByteArrayLiteral("SECOND-MULTILINE-SECRET"));
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(QByteArrayLiteral(",\r\n"));
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(QByteArrayLiteral("THIRD-MULTILINE-SECRET"));
        escapedMultilineArray.append(quote);
        escapedMultilineArray.append(
                QByteArrayLiteral("\r\n]\r\n}\r\nhealth=after-multiline-array\r\n"));
        const SanitizedChunk escapedMultilineArraySanitized = sanitize(
                escapedMultilineArray);
        CHECK(!escapedMultilineArraySanitized.data.contains(
                "FIRST-MULTILINE-SECRET"));
        CHECK(!escapedMultilineArraySanitized.data.contains(
                "SECOND-MULTILINE-SECRET"));
        CHECK(!escapedMultilineArraySanitized.data.contains(
                "THIRD-MULTILINE-SECRET"));
        CHECK(escapedMultilineArraySanitized.streamState.pendingSecretKind
              == PendingSecretKind::Array);
        CHECK(escapedMultilineArraySanitized.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(escapedMultilineArraySanitized.streamState.pendingSecretWhitespaceBytes
              == MaximumPendingSecretWhitespaceBytes);

        QByteArray escapedSpoofedArray = QByteArrayLiteral(
                "health=before-spoofed-array\r\npayload={");
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(QByteArrayLiteral("additional_secrets"));
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(QByteArrayLiteral(":\r\n[\r\n"));
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(QByteArrayLiteral("FIRST]}"));
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(QByteArrayLiteral(",\r\n"));
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(QByteArrayLiteral("SECOND-SPOOF-SECRET"));
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(QByteArrayLiteral(",\r\n"));
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(QByteArrayLiteral("THIRD-SPOOF-SENTINEL"));
        escapedSpoofedArray.append(quote);
        escapedSpoofedArray.append(
                QByteArrayLiteral("\r\n]\r\n}\r\nhealth=after-spoofed-array\r\n"));
        const SanitizedChunk escapedSpoofedArraySanitized = sanitize(
                escapedSpoofedArray);
        CHECK(!escapedSpoofedArraySanitized.data.contains("FIRST]}"));
        CHECK(!escapedSpoofedArraySanitized.data.contains(
                "SECOND-SPOOF-SECRET"));
        CHECK(!escapedSpoofedArraySanitized.data.contains(
                "THIRD-SPOOF-SENTINEL"));
        CHECK(escapedSpoofedArraySanitized.streamState.pendingSecretKind
              == PendingSecretKind::Array);
        CHECK(escapedSpoofedArraySanitized.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
    }

    QByteArray longBackslashControl = QByteArrayLiteral(
            "health=before-long-backslash-control value=");
    longBackslashControl.append(QByteArray(1024 * 1024, '\\'));
    longBackslashControl.append(
            QByteArrayLiteral("\nhealth=after-long-backslash-control\n"));
    CHECK(sanitize(longBackslashControl).data == longBackslashControl);

    QByteArray benignEscapedText = QByteArrayLiteral("message=");
    benignEscapedText.append(serializedQuote(1));
    benignEscapedText.append(QByteArrayLiteral("password required=false"));
    benignEscapedText.append(serializedQuote(1));
    benignEscapedText.append(QByteArrayLiteral(" health=healthy\n"));
    CHECK(sanitize(benignEscapedText).data == benignEscapedText);

    const QByteArray escapedQuote = serializedQuote(1);
    QByteArray escapedScalarKeyPrefix = QByteArrayLiteral(
            "health=before-escaped-scalar-boundary\npayload={");
    escapedScalarKeyPrefix.append(escapedQuote);
    escapedScalarKeyPrefix.append(QByteArrayLiteral("password"));
    escapedScalarKeyPrefix.append(escapedQuote);
    QByteArray escapedScalarKeySuffix = QByteArrayLiteral(":\n");
    escapedScalarKeySuffix.append(escapedQuote);
    escapedScalarKeySuffix.append(escapedScalarSecret);
    escapedScalarKeySuffix.append(escapedQuote);
    escapedScalarKeySuffix.append(
            QByteArrayLiteral("\nhealth=after-escaped-scalar-boundary\n"));
    const SanitizedChunk escapedScalarKey = sanitize(escapedScalarKeyPrefix);
    CHECK(escapedScalarKey.streamState.pendingSecretKind
          == PendingSecretKind::Scalar);
    CHECK(escapedScalarKey.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    ChunkContext escapedScalarContinuationContext;
    escapedScalarContinuationContext.streamState = escapedScalarKey.streamState;
    const SanitizedChunk escapedScalarContinuation = sanitize(
            escapedScalarKeySuffix, escapedScalarContinuationContext);
    CHECK(!escapedScalarContinuation.data.contains(escapedScalarSecret));
    CHECK(escapedScalarContinuation.data.contains(
            "health=after-escaped-scalar-boundary"));

    const StreamState escapedScalarInitialOffsetState = advanceStreamState(
            {}, escapedScalarKeyPrefix);
    const StreamBoundary escapedScalarInitialOffsetBoundary = inspectStreamBoundary(
            escapedScalarKeyPrefix.right(MaximumPrivateKeyMarkerBytes),
            escapedScalarKeySuffix,
            escapedScalarInitialOffsetState);
    ChunkContext escapedScalarInitialOffsetContext;
    escapedScalarInitialOffsetContext.startsInsideRecord = true;
    escapedScalarInitialOffsetContext.streamState = escapedScalarInitialOffsetState;
    escapedScalarInitialOffsetContext.boundaryPendingSecretKind =
            escapedScalarInitialOffsetBoundary.pendingSecretKind;
    escapedScalarInitialOffsetContext.boundaryPendingSecretPhase =
            escapedScalarInitialOffsetBoundary.pendingSecretPhase;
    escapedScalarInitialOffsetContext.boundaryPendingSecretCharacters =
            escapedScalarInitialOffsetBoundary.pendingSecretCharactersInInput;
    escapedScalarInitialOffsetContext.boundaryPendingSecretWhitespaceBytes =
            escapedScalarInitialOffsetBoundary.pendingSecretWhitespaceBytes;
    const SanitizedChunk escapedScalarInitialOffsetContinuation = sanitize(
            escapedScalarKeySuffix, escapedScalarInitialOffsetContext);
    CHECK(escapedScalarInitialOffsetState.pendingSecretKind
          == PendingSecretKind::Scalar);
    CHECK(escapedScalarInitialOffsetState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(!escapedScalarInitialOffsetContinuation.data.contains(
            escapedScalarSecret));
    CHECK(escapedScalarInitialOffsetContinuation.data.contains(
            "health=after-escaped-scalar-boundary"));

    QByteArray escapedArrayKeyPrefix = QByteArrayLiteral(
            "health=before-escaped-array-boundary\npayload={");
    escapedArrayKeyPrefix.append(escapedQuote);
    escapedArrayKeyPrefix.append(QByteArrayLiteral("additional_secrets"));
    escapedArrayKeyPrefix.append(escapedQuote);
    QByteArray escapedArrayKeySuffix = QByteArrayLiteral(":\n[");
    escapedArrayKeySuffix.append(escapedQuote);
    escapedArrayKeySuffix.append(escapedArraySecret);
    escapedArrayKeySuffix.append(escapedQuote);
    escapedArrayKeySuffix.append(
            QByteArrayLiteral("]\nhealth=after-escaped-array-boundary\n"));
    const SanitizedChunk escapedArrayKey = sanitize(escapedArrayKeyPrefix);
    CHECK(escapedArrayKey.streamState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(escapedArrayKey.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    ChunkContext escapedArrayContinuationContext;
    escapedArrayContinuationContext.streamState = escapedArrayKey.streamState;
    const SanitizedChunk escapedArrayContinuation = sanitize(
            escapedArrayKeySuffix, escapedArrayContinuationContext);
    CHECK(!escapedArrayContinuation.data.contains(escapedArraySecret));
    CHECK(escapedArrayContinuation.streamState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(escapedArrayContinuation.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);

    const StreamState escapedArrayInitialOffsetState = advanceStreamState(
            {}, escapedArrayKeyPrefix);
    const StreamBoundary escapedArrayInitialOffsetBoundary = inspectStreamBoundary(
            escapedArrayKeyPrefix.right(MaximumPrivateKeyMarkerBytes),
            escapedArrayKeySuffix,
            escapedArrayInitialOffsetState);
    ChunkContext escapedArrayInitialOffsetContext;
    escapedArrayInitialOffsetContext.startsInsideRecord = true;
    escapedArrayInitialOffsetContext.streamState = escapedArrayInitialOffsetState;
    escapedArrayInitialOffsetContext.boundaryPendingSecretKind =
            escapedArrayInitialOffsetBoundary.pendingSecretKind;
    escapedArrayInitialOffsetContext.boundaryPendingSecretPhase =
            escapedArrayInitialOffsetBoundary.pendingSecretPhase;
    escapedArrayInitialOffsetContext.boundaryPendingSecretCharacters =
            escapedArrayInitialOffsetBoundary.pendingSecretCharactersInInput;
    escapedArrayInitialOffsetContext.boundaryPendingSecretWhitespaceBytes =
            escapedArrayInitialOffsetBoundary.pendingSecretWhitespaceBytes;
    const SanitizedChunk escapedArrayInitialOffsetContinuation = sanitize(
            escapedArrayKeySuffix, escapedArrayInitialOffsetContext);
    CHECK(escapedArrayInitialOffsetState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(escapedArrayInitialOffsetState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(!escapedArrayInitialOffsetContinuation.data.contains(
            escapedArraySecret));
    CHECK(escapedArrayInitialOffsetContinuation.streamState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(escapedArrayInitialOffsetContinuation.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);

    QByteArray escapedScalarSplitLeft = QByteArrayLiteral("payload={");
    escapedScalarSplitLeft.append(escapedQuote);
    escapedScalarSplitLeft.append(QByteArrayLiteral("passwo"));
    QByteArray escapedScalarSplitRight = QByteArrayLiteral("rd");
    escapedScalarSplitRight.append(escapedQuote);
    escapedScalarSplitRight.append(QByteArrayLiteral(":\n"));
    escapedScalarSplitRight.append(escapedQuote);
    escapedScalarSplitRight.append(escapedScalarSecret);
    escapedScalarSplitRight.append(escapedQuote);
    escapedScalarSplitRight.append(
            QByteArrayLiteral("\nhealth=after-escaped-scalar-split\n"));
    const StreamBoundary escapedScalarSplitBoundary = inspectStreamBoundary(
            escapedScalarSplitLeft, escapedScalarSplitRight);
    CHECK(escapedScalarSplitBoundary.pendingSecretKind
          == PendingSecretKind::Scalar);
    CHECK(escapedScalarSplitBoundary.pendingSecretPhase
          == PendingSecretPhase::RedactingValue);
    ChunkContext escapedScalarSplitContext;
    escapedScalarSplitContext.startsInsideRecord = true;
    escapedScalarSplitContext.boundaryPendingSecretKind =
            escapedScalarSplitBoundary.pendingSecretKind;
    escapedScalarSplitContext.boundaryPendingSecretPhase =
            escapedScalarSplitBoundary.pendingSecretPhase;
    escapedScalarSplitContext.boundaryPendingSecretCharacters =
            escapedScalarSplitBoundary.pendingSecretCharactersInInput;
    escapedScalarSplitContext.boundaryPendingSecretWhitespaceBytes =
            escapedScalarSplitBoundary.pendingSecretWhitespaceBytes;
    const SanitizedChunk escapedScalarSplit = sanitize(
            escapedScalarSplitRight, escapedScalarSplitContext);
    CHECK(!escapedScalarSplit.data.contains(escapedScalarSecret));
    CHECK(escapedScalarSplit.data.contains("health=after-escaped-scalar-split"));

    ChunkContext partialScalarKeyContext;
    partialScalarKeyContext.endsInsideRecord = true;
    const SanitizedChunk partialScalarKey = sanitize(QByteArrayLiteral(
            "health=before-partial-key\npassword:"), partialScalarKeyContext);
    CHECK(partialScalarKey.streamState.pendingSecretKind == PendingSecretKind::Scalar);
    CHECK(partialScalarKey.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingValue);
    ChunkContext partialScalarContinuationContext;
    partialScalarContinuationContext.streamState = partialScalarKey.streamState;
    const SanitizedChunk partialScalarContinuation = sanitize(QByteArrayLiteral(
            "\n\"partial-key-next-chunk-secret\"\nhealth=after-partial-key\n"),
            partialScalarContinuationContext);
    CHECK(!partialScalarContinuation.data.contains("partial-key-next-chunk-secret"));
    CHECK(partialScalarContinuation.data.contains("health=after-partial-key"));

    const QByteArray splitScalarKeyLeft = QByteArrayLiteral(
            "health=before-split-scalar\npasswo");
    const QByteArray splitScalarKeyRight = QByteArrayLiteral(
            "rd\n:\n\"split-key-scalar-secret\"\nhealth=after-split-scalar\n");
    const StreamBoundary splitScalarKeyBoundary = inspectStreamBoundary(
            splitScalarKeyLeft, splitScalarKeyRight);
    CHECK(splitScalarKeyBoundary.pendingSecretKind == PendingSecretKind::Scalar);
    CHECK(splitScalarKeyBoundary.pendingSecretPhase
          == PendingSecretPhase::RedactingValue);
    ChunkContext splitScalarKeyContext;
    splitScalarKeyContext.startsInsideRecord = true;
    splitScalarKeyContext.boundaryPendingSecretKind =
            splitScalarKeyBoundary.pendingSecretKind;
    splitScalarKeyContext.boundaryPendingSecretPhase =
            splitScalarKeyBoundary.pendingSecretPhase;
    splitScalarKeyContext.boundaryPendingSecretCharacters =
            splitScalarKeyBoundary.pendingSecretCharactersInInput;
    splitScalarKeyContext.boundaryPendingSecretWhitespaceBytes =
            splitScalarKeyBoundary.pendingSecretWhitespaceBytes;
    const SanitizedChunk splitScalarKey = sanitize(
            splitScalarKeyRight, splitScalarKeyContext);
    CHECK(!splitScalarKey.data.contains("split-key-scalar-secret"));
    CHECK(splitScalarKey.data.contains("health=after-split-scalar"));

    const QByteArray splitArrayKeyLeft = QByteArrayLiteral(
            "health=before-split-array\nadditional_sec");
    QByteArray splitArrayKeyRight = QByteArrayLiteral("rets\n:\n");
    splitArrayKeyRight.append(QByteArray(4096, ' '));
    splitArrayKeyRight.append(
            "[\"split-key-array-secret\"]\nhealth=after-split-array\n");
    const StreamBoundary splitArrayKeyBoundary = inspectStreamBoundary(
            splitArrayKeyLeft, splitArrayKeyRight);
    CHECK(splitArrayKeyBoundary.pendingSecretKind == PendingSecretKind::Array);
    CHECK(splitArrayKeyBoundary.pendingSecretPhase
          == PendingSecretPhase::AwaitingValue);
    ChunkContext splitArrayKeyContext;
    splitArrayKeyContext.startsInsideRecord = true;
    splitArrayKeyContext.boundaryPendingSecretKind =
            splitArrayKeyBoundary.pendingSecretKind;
    splitArrayKeyContext.boundaryPendingSecretPhase =
            splitArrayKeyBoundary.pendingSecretPhase;
    splitArrayKeyContext.boundaryPendingSecretCharacters =
            splitArrayKeyBoundary.pendingSecretCharactersInInput;
    splitArrayKeyContext.boundaryPendingSecretWhitespaceBytes =
            splitArrayKeyBoundary.pendingSecretWhitespaceBytes;
    const SanitizedChunk splitArrayKey = sanitize(
            splitArrayKeyRight, splitArrayKeyContext);
    CHECK(!splitArrayKey.data.contains("split-key-array-secret"));
    CHECK(splitArrayKey.data.contains("health=after-split-array"));

    QByteArray splitArrayScanMiddle = QByteArrayLiteral("rets\n:\n");
    splitArrayScanMiddle.append(QByteArray(4096, '\t'));
    StreamState splitArrayReconstructedState = advanceStreamState(
            splitArrayKeyLeft, splitArrayScanMiddle);
    CHECK(splitArrayReconstructedState.pendingSecretKind == PendingSecretKind::Array);
    CHECK(splitArrayReconstructedState.pendingSecretPhase
          == PendingSecretPhase::AwaitingValue);
    ChunkContext splitArrayReconstructedContext;
    splitArrayReconstructedContext.streamState = splitArrayReconstructedState;
    const SanitizedChunk splitArrayReconstructedContinuation = sanitize(
            QByteArrayLiteral(
                    "[\"split-key-reconstructed-array-secret\"]\n"
                    "health=after-split-array-scan\n"),
            splitArrayReconstructedContext);
    CHECK(!splitArrayReconstructedContinuation.data.contains(
            "split-key-reconstructed-array-secret"));
    CHECK(splitArrayReconstructedContinuation.data.contains(
            "health=after-split-array-scan"));

    StreamState reconstructedScalarState = advanceStreamState(
            {}, QByteArrayLiteral("health=before-scan\n\"private_key\":\n"));
    CHECK(reconstructedScalarState.pendingSecretKind == PendingSecretKind::Scalar);
    CHECK(reconstructedScalarState.pendingSecretPhase
          == PendingSecretPhase::AwaitingValue);
    const QByteArray reconstructedScalarGap(4096, ' ');
    reconstructedScalarState = advanceStreamState(
            QByteArrayLiteral("\"private_key\":\n"),
            reconstructedScalarGap,
            reconstructedScalarState);
    CHECK(reconstructedScalarState.pendingSecretWhitespaceBytes
          == reconstructedScalarGap.size() + 1);
    ChunkContext reconstructedScalarContext;
    reconstructedScalarContext.streamState = reconstructedScalarState;
    const SanitizedChunk reconstructedScalarContinuation = sanitize(QByteArrayLiteral(
            "scan-reconstructed-scalar-secret\nhealth=after-scan-scalar\n"),
            reconstructedScalarContext);
    CHECK(!reconstructedScalarContinuation.data.contains(
            "scan-reconstructed-scalar-secret"));
    CHECK(reconstructedScalarContinuation.data.contains("health=after-scan-scalar"));

    const SanitizedChunk arrayGapStart = sanitize(QByteArrayLiteral(
            "additional_secrets=\n"));
    CHECK(arrayGapStart.streamState.pendingSecretKind == PendingSecretKind::Array);
    CHECK(arrayGapStart.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingValue);
    StreamState arrayGapState = arrayGapStart.streamState;
    for (int i = 0; i < 3; ++i) {
        ChunkContext gapContext;
        gapContext.streamState = arrayGapState;
        QByteArray gap(2048, ' ');
        gap.append('\n');
        const SanitizedChunk gapChunk = sanitize(gap, gapContext);
        arrayGapState = gapChunk.streamState;
        CHECK(arrayGapState.pendingSecretKind == PendingSecretKind::Array);
        CHECK(arrayGapState.pendingSecretPhase == PendingSecretPhase::AwaitingValue);
    }
    ChunkContext arrayGapContinuationContext;
    arrayGapContinuationContext.streamState = arrayGapState;
    const SanitizedChunk arrayGapContinuation = sanitize(QByteArrayLiteral(
            "[\n\"array-after-long-gap-secret\"\n]\nhealth=after-array-gap\n"),
            arrayGapContinuationContext);
    CHECK(!arrayGapContinuation.data.contains("array-after-long-gap-secret"));
    CHECK(arrayGapContinuation.data.contains("health=after-array-gap"));
    CHECK(!arrayGapContinuation.streamState.secretArrayOpen);
    CHECK(arrayGapContinuation.streamState.pendingSecretKind == PendingSecretKind::None);

    StreamState reconstructedArrayState = advanceStreamState(
            {}, QByteArrayLiteral("telemt_additional_secrets:\n"));
    const QByteArray reconstructedArrayGap(8192, '\t');
    reconstructedArrayState = advanceStreamState(
            QByteArrayLiteral("telemt_additional_secrets:\n"),
            reconstructedArrayGap,
            reconstructedArrayState);
    CHECK(reconstructedArrayState.pendingSecretKind == PendingSecretKind::Array);
    CHECK(reconstructedArrayState.pendingSecretWhitespaceBytes
          == reconstructedArrayGap.size() + 1);
    ChunkContext reconstructedArrayContext;
    reconstructedArrayContext.streamState = reconstructedArrayState;
    const SanitizedChunk reconstructedArrayContinuation = sanitize(QByteArrayLiteral(
            "[\"scan-reconstructed-array-secret\"]\nhealth=after-scan-array\n"),
            reconstructedArrayContext);
    CHECK(!reconstructedArrayContinuation.data.contains(
            "scan-reconstructed-array-secret"));
    CHECK(reconstructedArrayContinuation.data.contains("health=after-scan-array"));

    ChunkContext overflowContext;
    overflowContext.streamState = arrayGapStart.streamState;
    const SanitizedChunk overflowGap = sanitize(
            QByteArray(MaximumPendingSecretWhitespaceBytes + 1, ' '),
            overflowContext);
    CHECK(overflowGap.streamState.pendingSecretKind == PendingSecretKind::Array);
    CHECK(overflowGap.streamState.pendingSecretPhase
          == PendingSecretPhase::OverflowAwaitingValue);
    CHECK(overflowGap.streamState.pendingSecretWhitespaceBytes
          == MaximumPendingSecretWhitespaceBytes);
    ChunkContext overflowStillPendingContext;
    overflowStillPendingContext.streamState = overflowGap.streamState;
    const SanitizedChunk overflowStillPending = sanitize(
            QByteArray(4096, '\n'), overflowStillPendingContext);
    CHECK(overflowStillPending.data == QByteArrayLiteral("***"));
    CHECK(overflowStillPending.streamState.pendingSecretPhase
          == PendingSecretPhase::OverflowAwaitingValue);
    ChunkContext overflowRecoveryContext;
    overflowRecoveryContext.streamState = overflowStillPending.streamState;
    const SanitizedChunk overflowRecovery = sanitize(QByteArrayLiteral(
            "[\"array-after-overflow-secret\"]\nhealth=after-overflow\n"),
            overflowRecoveryContext);
    CHECK(!overflowRecovery.data.contains("array-after-overflow-secret"));
    CHECK(overflowRecovery.data.contains("health=after-overflow"));
    CHECK(overflowRecovery.streamState.pendingSecretPhase == PendingSecretPhase::None);

    const SanitizedChunk arrayBeforeSeparator = sanitize(QByteArrayLiteral(
            "\"additional_secrets\"\n"));
    CHECK(arrayBeforeSeparator.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    ChunkContext arraySeparatorGapOneContext;
    arraySeparatorGapOneContext.streamState = arrayBeforeSeparator.streamState;
    const SanitizedChunk arraySeparatorGapOne = sanitize(
            QByteArray(MaximumPendingSecretWhitespaceBytes / 2, ' '),
            arraySeparatorGapOneContext);
    ChunkContext arraySeparatorGapTwoContext;
    arraySeparatorGapTwoContext.streamState = arraySeparatorGapOne.streamState;
    const SanitizedChunk arraySeparatorGapTwo = sanitize(
            QByteArray(MaximumPendingSecretWhitespaceBytes / 2 + 1, '\t'),
            arraySeparatorGapTwoContext);
    CHECK(arraySeparatorGapTwo.streamState.pendingSecretPhase
          == PendingSecretPhase::OverflowAwaitingSeparator);
    ChunkContext arraySeparatorContext;
    arraySeparatorContext.streamState = arraySeparatorGapTwo.streamState;
    const SanitizedChunk arraySeparator = sanitize(QByteArrayLiteral(":\n"),
                                                    arraySeparatorContext);
    CHECK(arraySeparator.streamState.pendingSecretPhase
          == PendingSecretPhase::OverflowAwaitingValue);
    ChunkContext arrayAfterSeparatorGapContext;
    arrayAfterSeparatorGapContext.streamState = arraySeparator.streamState;
    const SanitizedChunk arrayAfterSeparatorGap = sanitize(
            QByteArray(4096, '\n'), arrayAfterSeparatorGapContext);
    CHECK(arrayAfterSeparatorGap.streamState.pendingSecretPhase
          == PendingSecretPhase::OverflowAwaitingValue);
    ChunkContext arrayAfterSeparatorValueContext;
    arrayAfterSeparatorValueContext.streamState = arrayAfterSeparatorGap.streamState;
    const SanitizedChunk arrayAfterSeparatorValue = sanitize(QByteArrayLiteral(
            "[\"array-after-overflow-before-separator-secret\"]\n"
            "health=after-overflow-before-separator\n"),
            arrayAfterSeparatorValueContext);
    CHECK(!arrayAfterSeparatorValue.data.contains(
            "array-after-overflow-before-separator-secret"));
    CHECK(arrayAfterSeparatorValue.data.contains(
            "health=after-overflow-before-separator"));
    CHECK(arrayAfterSeparatorValue.streamState.pendingSecretPhase
          == PendingSecretPhase::None);

    ChunkContext scalarSeparatorGapContext;
    scalarSeparatorGapContext.streamState = keyOnlyChunk.streamState;
    const SanitizedChunk scalarSeparatorGap = sanitize(
            QByteArray(MaximumPendingSecretWhitespaceBytes + 1, ' '),
            scalarSeparatorGapContext);
    CHECK(scalarSeparatorGap.streamState.pendingSecretPhase
          == PendingSecretPhase::OverflowAwaitingSeparator);
    ChunkContext scalarSeparatorContext;
    scalarSeparatorContext.streamState = scalarSeparatorGap.streamState;
    const SanitizedChunk scalarSeparator = sanitize(QByteArrayLiteral(":\n"),
                                                     scalarSeparatorContext);
    CHECK(scalarSeparator.streamState.pendingSecretPhase
          == PendingSecretPhase::OverflowAwaitingValue);
    ChunkContext scalarAfterSeparatorContext;
    scalarAfterSeparatorContext.streamState = scalarSeparator.streamState;
    const SanitizedChunk scalarAfterSeparator = sanitize(QByteArrayLiteral(
            "scalar-after-overflow-before-separator-secret\n"
            "health=after-scalar-overflow-before-separator\n"),
            scalarAfterSeparatorContext);
    CHECK(!scalarAfterSeparator.data.contains(
            "scalar-after-overflow-before-separator-secret"));
    CHECK(scalarAfterSeparator.data.contains(
            "health=after-scalar-overflow-before-separator"));
    CHECK(scalarAfterSeparator.streamState.pendingSecretPhase
          == PendingSecretPhase::None);

    ChunkContext unexpectedArrayContext;
    unexpectedArrayContext.streamState = arrayGapStart.streamState;
    const SanitizedChunk unexpectedArrayValue = sanitize(QByteArrayLiteral(
            "unexpected-array-secret\nhealth=after-unexpected-array\n"),
            unexpectedArrayContext);
    CHECK(!unexpectedArrayValue.data.contains("unexpected-array-secret"));
    CHECK(unexpectedArrayValue.data.contains("health=after-unexpected-array"));
    CHECK(unexpectedArrayValue.streamState.pendingSecretPhase
          == PendingSecretPhase::None);

    const SanitizedChunk commandLineAndEscapedValues = sanitize(QByteArrayLiteral(
            "tool --token=cli-token-secret --password \"cli-\\\"password-secret\"\n"
            "payload={\"password\":\"json-\\\"password-secret\"}\n"
            "pass=alpha;beta,gamma\nhealth=healthy\n"));
    CHECK(!commandLineAndEscapedValues.data.contains("cli-token-secret"));
    CHECK(!commandLineAndEscapedValues.data.contains("password-secret"));
    CHECK(!commandLineAndEscapedValues.data.contains("alpha"));
    CHECK(!commandLineAndEscapedValues.data.contains("beta"));
    CHECK(!commandLineAndEscapedValues.data.contains("gamma"));
    CHECK(commandLineAndEscapedValues.data.contains("health=healthy"));

    const SanitizedChunk openVpnStaticKey = sanitize(QByteArrayLiteral(
            "health=before\n-----BEGIN OpenVPN Static key V1-----\n"
            "0123456789abcdef-openvpn-secret\n"
            "-----END OpenVPN Static key V1-----\nhealth=after\n"));
    CHECK(openVpnStaticKey.streamState.blockKind == SecretBlockKind::None);
    CHECK(!openVpnStaticKey.data.contains("openvpn-secret"));
    CHECK(openVpnStaticKey.data.contains("health=before"));
    CHECK(openVpnStaticKey.data.contains("health=after"));

    const SanitizedChunk inlineTlsAuthFirst = sanitize(QByteArrayLiteral(
            "<tls-auth>\ninline-auth-secret\n"));
    CHECK(inlineTlsAuthFirst.streamState.blockKind == SecretBlockKind::TlsAuth);
    CHECK(!inlineTlsAuthFirst.data.contains("inline-auth-secret"));
    ChunkContext inlineTlsAuthContext;
    inlineTlsAuthContext.streamState = inlineTlsAuthFirst.streamState;
    const SanitizedChunk inlineTlsAuthSecond = sanitize(QByteArrayLiteral(
            "continued-auth-secret\n</tls-auth>\nhealth=after-auth\n"),
            inlineTlsAuthContext);
    CHECK(inlineTlsAuthSecond.streamState.blockKind == SecretBlockKind::None);
    CHECK(!inlineTlsAuthSecond.data.contains("continued-auth-secret"));
    CHECK(inlineTlsAuthSecond.data.contains("health=after-auth"));

    const SanitizedChunk inlineTlsCrypt = sanitize(QByteArrayLiteral(
            "<tls-crypt-v2>\ninline-crypt-secret\n</tls-crypt-v2>\nhealth=after-crypt\n"));
    CHECK(inlineTlsCrypt.streamState.blockKind == SecretBlockKind::None);
    CHECK(!inlineTlsCrypt.data.contains("inline-crypt-secret"));
    CHECK(inlineTlsCrypt.data.contains("health=after-crypt"));

    const QByteArray splitOpenVpnLeft = QByteArrayLiteral(
            "health=healthy\n-----BEGIN OpenVPN Static ");
    const QByteArray splitOpenVpnRight = QByteArrayLiteral(
            "key V1-----\nsplit-openvpn-secret\n-----END OpenVPN Static key V1-----\n"
            "route=10.5.0.0/16\n");
    const StreamBoundary splitOpenVpnBoundary = inspectStreamBoundary(
            splitOpenVpnLeft, splitOpenVpnRight);
    CHECK(splitOpenVpnBoundary.beginBlockKind == SecretBlockKind::OpenVpnStaticKey);
    ChunkContext splitOpenVpnContext;
    splitOpenVpnContext.startsInsideRecord = true;
    splitOpenVpnContext.boundaryBlockKind = splitOpenVpnBoundary.beginBlockKind;
    const SanitizedChunk splitOpenVpn = sanitize(splitOpenVpnRight, splitOpenVpnContext);
    CHECK(splitOpenVpn.streamState.blockKind == SecretBlockKind::None);
    CHECK(!splitOpenVpn.data.contains("split-openvpn-secret"));
    CHECK(splitOpenVpn.data.contains("route=10.5.0.0/16"));

    const SanitizedChunk arrayFirst = sanitize(QByteArrayLiteral(
            "mtproxy_additional_secrets=[\n\"array-first-secret\",\n"));
    CHECK(arrayFirst.streamState.secretArrayOpen);
    CHECK(arrayFirst.streamState.secretArrayDepth == 1);
    CHECK(!arrayFirst.data.contains("array-first-secret"));
    ChunkContext arrayContinuationContext;
    arrayContinuationContext.streamState = arrayFirst.streamState;
    const SanitizedChunk arraySecond = sanitize(QByteArrayLiteral(
            "\"array-second-secret\"\n]\nhealth=after-array\n"),
            arrayContinuationContext);
    CHECK(!arraySecond.streamState.secretArrayOpen);
    CHECK(!arraySecond.data.contains("array-second-secret"));
    CHECK(arraySecond.data.contains("health=after-array"));

    const QByteArray splitArrayLeft = QByteArrayLiteral(
            "health=healthy\ntelemt_additional_secr");
    const QByteArray splitArrayRight = QByteArrayLiteral(
            "ets=[\n\"split-array-secret\"\n]\nroute=10.6.0.0/16\n");
    const StreamBoundary splitArrayBoundary = inspectStreamBoundary(
            splitArrayLeft, splitArrayRight);
    CHECK(splitArrayBoundary.secretArrayStartCharactersInInput > 0);
    ChunkContext splitArrayContext;
    splitArrayContext.startsInsideRecord = true;
    splitArrayContext.secretArrayStartCharacters =
            splitArrayBoundary.secretArrayStartCharactersInInput;
    const SanitizedChunk splitArray = sanitize(splitArrayRight, splitArrayContext);
    CHECK(!splitArray.streamState.secretArrayOpen);
    CHECK(!splitArray.data.contains("split-array-secret"));
    CHECK(splitArray.data.contains("route=10.6.0.0/16"));

    StreamState conceptualState;
    QByteArray conceptualLookbehind;
    const QByteArray scanBlock(1024 * 1024, 'x');
    qsizetype conceptualBytes = 0;
    while (conceptualBytes <= MaximumInputBytes) {
        conceptualState = advanceStreamState(
                conceptualLookbehind, scanBlock, conceptualState);
        conceptualLookbehind = scanBlock.right(MaximumPrivateKeyMarkerBytes);
        conceptualBytes += scanBlock.size();
    }
    const QByteArray conceptualArrayStart = QByteArrayLiteral(
            "\nadditional_secrets=[\n\"before-conceptual-boundary\",\n");
    conceptualState = advanceStreamState(
            conceptualLookbehind, conceptualArrayStart, conceptualState);
    CHECK(conceptualBytes + conceptualArrayStart.size() > MaximumInputBytes);
    CHECK(conceptualState.secretArrayOpen);
    ChunkContext conceptualContinuationContext;
    conceptualContinuationContext.streamState = conceptualState;
    const SanitizedChunk conceptualContinuation = sanitize(QByteArrayLiteral(
            "\"after-conceptual-boundary\"\n]\nhealth=after-conceptual-boundary\n"),
            conceptualContinuationContext);
    CHECK(!conceptualContinuation.streamState.secretArrayOpen);
    CHECK(!conceptualContinuation.data.contains("after-conceptual-boundary\""));
    CHECK(conceptualContinuation.data.contains("health=after-conceptual-boundary"));

    QByteArray manyArrays;
    for (int i = 0; i < 4096; ++i) {
        manyArrays.append("additional_secrets=[\"many-array-secret\"]\n");
    }
    manyArrays.append("health=after-many-arrays\n");
    const SanitizedChunk manyArraysSanitized = sanitize(manyArrays);
    CHECK(!manyArraysSanitized.data.contains("many-array-secret"));
    CHECK(manyArraysSanitized.data.contains("health=after-many-arrays"));

    const SanitizedChunk splitCredential = sanitize(
            QByteArrayLiteral("continuation-of-a-secret\nhealth=healthy\ntoken=split"),
            chunkContext(true, true, false));
    CHECK(!splitCredential.data.contains("continuation-of-a-secret"));
    CHECK(!splitCredential.data.contains("split"));
    CHECK(splitCredential.data.contains("health=healthy"));

    const QByteArray benign = QByteArrayLiteral(
            "token bucket available=42\npassword required=false\n"
            "route domain=api.example.com ip=203.0.113.9 health=healthy\n");
    CHECK(sanitize(benign).data == benign);

    const auto sanitizeAcrossSplit = [](const QByteArray &raw, qsizetype split) {
        const QByteArray left = raw.first(split);
        const QByteArray right = raw.sliced(split);
        ChunkContext leftContext;
        leftContext.endsInsideRecord = !right.isEmpty()
                && !left.endsWith('\n') && !left.endsWith('\r');
        const SanitizedChunk leftSanitized = sanitize(left, leftContext);
        const StreamBoundary boundary = inspectStreamBoundary(
                left.right(MaximumPrivateKeyMarkerBytes),
                right,
                leftSanitized.streamState);
        ChunkContext rightContext;
        rightContext.startsInsideRecord = !left.isEmpty()
                && !left.endsWith('\n') && !left.endsWith('\r');
        rightContext.streamState = leftSanitized.streamState;
        rightContext.boundaryBlockKind = boundary.beginBlockKind;
        rightContext.secretBlockEndMarkerCharacters =
                boundary.endBlockMarkerCharactersInInput;
        rightContext.secretArrayStartCharacters =
                boundary.secretArrayStartCharactersInInput;
        rightContext.boundaryPendingSecretKind = boundary.pendingSecretKind;
        rightContext.boundaryPendingSecretPhase = boundary.pendingSecretPhase;
        rightContext.boundaryPendingSecretCharacters =
                boundary.pendingSecretCharactersInInput;
        rightContext.boundaryPendingSecretWhitespaceBytes =
                boundary.pendingSecretWhitespaceBytes;
        const SanitizedChunk rightSanitized = sanitize(right, rightContext);
        const QByteArray combinedSanitized = leftSanitized.data + rightSanitized.data;
        return combinedSanitized;
    };

    const auto sanitizeAfterInitialOffset = [](const QByteArray &raw,
                                                qsizetype split) {
        const QByteArray scannedPrefix = raw.first(split);
        const QByteArray sourceData = raw.sliced(split);
        const StreamState reconstructedState = advanceStreamState(
                {}, scannedPrefix);
        const StreamBoundary boundary = inspectStreamBoundary(
                scannedPrefix.right(MaximumPrivateKeyMarkerBytes),
                sourceData,
                reconstructedState);
        ChunkContext context;
        context.startsInsideRecord = split > 0
                && !scannedPrefix.endsWith('\n')
                && !scannedPrefix.endsWith('\r');
        context.streamState = reconstructedState;
        context.boundaryBlockKind = boundary.beginBlockKind;
        context.secretBlockEndMarkerCharacters =
                boundary.endBlockMarkerCharactersInInput;
        context.secretArrayStartCharacters =
                boundary.secretArrayStartCharactersInInput;
        context.boundaryPendingSecretKind = boundary.pendingSecretKind;
        context.boundaryPendingSecretPhase = boundary.pendingSecretPhase;
        context.boundaryPendingSecretCharacters =
                boundary.pendingSecretCharactersInInput;
        context.boundaryPendingSecretWhitespaceBytes =
                boundary.pendingSecretWhitespaceBytes;
        return sanitize(sourceData, context);
    };

    const QByteArray scalarSplitSweep = QByteArrayLiteral(
            "health=before-scalar-sweep\n\"password\"\n:\n"
            "\"scalar-split-sweep-secret\"\nhealth=after-scalar-sweep\n");
    for (qsizetype split = 1; split < scalarSplitSweep.size(); ++split) {
        const bool safe = !sanitizeAcrossSplit(scalarSplitSweep, split).contains(
                "scalar-split-sweep-secret");
        if (!safe) {
            QTextStream(stderr) << "scalar sweep leaked at split " << split << Qt::endl;
        }
        CHECK(safe);
    }

    QByteArray arraySplitSweep = QByteArrayLiteral(
            "health=before-array-sweep\n\"additional_secrets\"\n:\n");
    arraySplitSweep.append(QByteArray(1024, ' '));
    arraySplitSweep.append(
            "[\"array-split-sweep-secret\"]\nhealth=after-array-sweep\n");
    for (qsizetype split = 1; split < arraySplitSweep.size(); ++split) {
        const bool safe = !sanitizeAcrossSplit(arraySplitSweep, split).contains(
                "array-split-sweep-secret");
        if (!safe) {
            QTextStream(stderr) << "array sweep leaked at split " << split << Qt::endl;
        }
        CHECK(safe);
    }

    for (const qsizetype structuralBackslashes : {
                 qsizetype(1), qsizetype(2), qsizetype(3), qsizetype(7) }) {
        const QByteArray quote = serializedQuote(structuralBackslashes);
        QByteArray serializedScalarSweep = QByteArrayLiteral(
                "health=before-serialized-scalar-sweep\r\npayload={");
        serializedScalarSweep.append(quote);
        serializedScalarSweep.append(QByteArrayLiteral("password"));
        serializedScalarSweep.append(quote);
        serializedScalarSweep.append(QByteArrayLiteral(":\r\n"));
        serializedScalarSweep.append(quote);
        serializedScalarSweep.append(
                QByteArrayLiteral("SERIALIZED-SCALAR-SWEEP-SECRET"));
        serializedScalarSweep.append(quote);
        serializedScalarSweep.append(
                QByteArrayLiteral("\r\n}\r\nhealth=after-serialized-scalar-sweep\r\n"));
        for (qsizetype split = 1; split < serializedScalarSweep.size(); ++split) {
            CHECK(!sanitizeAcrossSplit(serializedScalarSweep, split).contains(
                    "SERIALIZED-SCALAR-SWEEP-SECRET"));
            CHECK(!sanitizeAfterInitialOffset(serializedScalarSweep, split)
                           .data.contains("SERIALIZED-SCALAR-SWEEP-SECRET"));
        }

        QByteArray serializedArraySweep = QByteArrayLiteral(
                "health=before-serialized-array-sweep\r\npayload={");
        serializedArraySweep.append(quote);
        serializedArraySweep.append(QByteArrayLiteral("additional_secrets"));
        serializedArraySweep.append(quote);
        serializedArraySweep.append(QByteArrayLiteral(":\r\n[\r\n"));
        serializedArraySweep.append(quote);
        serializedArraySweep.append(QByteArrayLiteral("FIRST]}"));
        serializedArraySweep.append(quote);
        serializedArraySweep.append(QByteArrayLiteral(",\r\n"));
        serializedArraySweep.append(quote);
        serializedArraySweep.append(QByteArrayLiteral("SECOND-SWEEP-SECRET"));
        serializedArraySweep.append(quote);
        serializedArraySweep.append(QByteArrayLiteral(",\r\n"));
        serializedArraySweep.append(quote);
        serializedArraySweep.append(QByteArrayLiteral("THIRD-SWEEP-SENTINEL"));
        serializedArraySweep.append(quote);
        serializedArraySweep.append(
                QByteArrayLiteral("\r\n]\r\n}\r\nhealth=after-serialized-array-sweep\r\n"));
        for (qsizetype split = 1; split < serializedArraySweep.size(); ++split) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(
                    serializedArraySweep, split);
            CHECK(!splitSanitized.contains("FIRST]}"));
            CHECK(!splitSanitized.contains("SECOND-SWEEP-SECRET"));
            CHECK(!splitSanitized.contains("THIRD-SWEEP-SENTINEL"));
            const SanitizedChunk initialOffsetSanitized = sanitizeAfterInitialOffset(
                    serializedArraySweep, split);
            CHECK(!initialOffsetSanitized.data.contains("FIRST]}"));
            CHECK(!initialOffsetSanitized.data.contains("SECOND-SWEEP-SECRET"));
            CHECK(!initialOffsetSanitized.data.contains("THIRD-SWEEP-SENTINEL"));
        }
    }

    const auto checkLongSerializedEnvelope = [&](const QByteArray &key,
                                                  bool arrayValue,
                                                  qsizetype structuralBackslashes,
                                                  bool exhaustive) {
        const QByteArray quote = serializedQuote(structuralBackslashes);
        const QByteArray prefix = QByteArrayLiteral(
                "health=before-long-envelope\r\npayload={");
        QByteArray envelope = quote;
        envelope.append(key);
        envelope.append(quote);
        envelope.append(QByteArrayLiteral(":\r\n"));
        QByteArray raw = prefix + envelope;
        if (arrayValue) {
            raw.append(QByteArrayLiteral("[\r\n"));
            raw.append(quote);
            raw.append(QByteArrayLiteral("LONG-ARRAY-FIRST]}"));
            raw.append(quote);
            raw.append(QByteArrayLiteral(",\r\n"));
            raw.append(quote);
            raw.append(QByteArrayLiteral("LONG-ARRAY-SECOND-SECRET"));
            raw.append(quote);
            raw.append(QByteArrayLiteral(",\r\n"));
            raw.append(quote);
            raw.append(QByteArrayLiteral("LONG-ARRAY-THIRD-SENTINEL"));
            raw.append(quote);
            raw.append(QByteArrayLiteral("]\r\n}\r\n"));
        } else {
            raw.append(quote);
            raw.append(QByteArrayLiteral("LONG-SCALAR-SECRET"));
            raw.append(quote);
            raw.append(QByteArrayLiteral("\r\n}\r\n"));
        }
        raw.append(QByteArrayLiteral("health=after-long-envelope\r\n"));

        QList<qsizetype> splitPositions;
        const qsizetype envelopeStart = prefix.size();
        const qsizetype envelopeEnd = envelopeStart + envelope.size();
        if (exhaustive) {
            for (qsizetype split = envelopeStart; split <= envelopeEnd; ++split) {
                splitPositions.append(split);
            }
        } else {
            const qsizetype openingRunStart = envelopeStart;
            const qsizetype keyStart = openingRunStart
                    + structuralBackslashes + 1;
            const qsizetype closingRunStart = keyStart + key.size();
            for (const qsizetype runOffset : {
                         qsizetype(1), qsizetype(64), qsizetype(127),
                         qsizetype(236), qsizetype(237), qsizetype(246),
                         qsizetype(247), qsizetype(255), qsizetype(256),
                         qsizetype(257), structuralBackslashes / 2,
                         structuralBackslashes - 1,
                         structuralBackslashes }) {
                if (runOffset >= 0 && runOffset <= structuralBackslashes) {
                    splitPositions.append(openingRunStart + runOffset);
                    splitPositions.append(closingRunStart + runOffset);
                }
            }
            splitPositions.append(keyStart);
            for (qsizetype keyOffset = 1; keyOffset <= key.size(); ++keyOffset) {
                splitPositions.append(keyStart + keyOffset);
            }
            splitPositions.append(envelopeEnd - 1);
            splitPositions.append(envelopeEnd);
        }

        for (const qsizetype split : splitPositions) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            if (arrayValue) {
                CHECK(!splitSanitized.contains("LONG-ARRAY-FIRST]}"));
                CHECK(!splitSanitized.contains("LONG-ARRAY-SECOND-SECRET"));
                CHECK(!splitSanitized.contains("LONG-ARRAY-THIRD-SENTINEL"));
                CHECK(!initialOffsetSanitized.data.contains("LONG-ARRAY-FIRST]}"));
                CHECK(!initialOffsetSanitized.data.contains(
                        "LONG-ARRAY-SECOND-SECRET"));
                CHECK(!initialOffsetSanitized.data.contains(
                        "LONG-ARRAY-THIRD-SENTINEL"));
            } else {
                CHECK(!splitSanitized.contains("LONG-SCALAR-SECRET"));
                CHECK(!initialOffsetSanitized.data.contains(
                        "LONG-SCALAR-SECRET"));
            }
        }
    };

    for (const qsizetype structuralBackslashes : {
                 qsizetype(65), qsizetype(127), qsizetype(237),
                 qsizetype(247), qsizetype(1024) }) {
        checkLongSerializedEnvelope(QByteArrayLiteral("password"), false,
                                    structuralBackslashes, true);
        checkLongSerializedEnvelope(QByteArrayLiteral("additional_secrets"), true,
                                    structuralBackslashes, true);
    }
    checkLongSerializedEnvelope(QByteArrayLiteral("password"), false,
                                qsizetype(65536), false);
    checkLongSerializedEnvelope(QByteArrayLiteral("additional_secrets"), true,
                                qsizetype(65536), false);

    QByteArray partialLongScalar = QByteArrayLiteral("payload={");
    partialLongScalar.append(serializedQuote(1024));
    partialLongScalar.append(QByteArrayLiteral("password"));
    partialLongScalar.append(QByteArray(512, '\\'));
    const SanitizedChunk partialLongScalarState = sanitize(partialLongScalar);
    CHECK(partialLongScalarState.streamState.pendingSecretKind
          == PendingSecretKind::Scalar);
    CHECK(partialLongScalarState.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(partialLongScalarState.streamState.pendingSecretWhitespaceBytes == 0);

    QByteArray partialLongArray = QByteArrayLiteral("payload={");
    partialLongArray.append(serializedQuote(1024));
    partialLongArray.append(QByteArrayLiteral("additional_secrets"));
    partialLongArray.append(QByteArray(512, '\\'));
    const SanitizedChunk partialLongArrayState = sanitize(partialLongArray);
    CHECK(partialLongArrayState.streamState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(partialLongArrayState.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(partialLongArrayState.streamState.pendingSecretWhitespaceBytes
          == MaximumPendingSecretWhitespaceBytes);

    QByteArray benignLongSerialized = QByteArrayLiteral("payload={");
    benignLongSerialized.append(serializedQuote(1024));
    benignLongSerialized.append(QByteArrayLiteral("public_key"));
    benignLongSerialized.append(serializedQuote(1024));
    benignLongSerialized.append(QByteArrayLiteral(":\"visible-diagnostic\"}\r\n"));
    CHECK(sanitize(benignLongSerialized).data == benignLongSerialized);

    const auto checkTrailingSerializedPendingAfterEarlierKey = [&]
            (const QByteArray &trailingKey, bool arrayValue) {
        const QByteArray quote = serializedQuote(1);
        QByteArray left = QByteArrayLiteral("payload={");
        left.append(quote);
        left.append(QByteArrayLiteral("password"));
        left.append(quote);
        left.append(QByteArrayLiteral(":"));
        left.append(quote);
        left.append(QByteArrayLiteral("FIRST-SERIALIZED-SECRET"));
        left.append(quote);
        left.append(QByteArrayLiteral(","));
        left.append(quote);
        left.append(trailingKey);
        left.append('\\');

        QByteArray right = QByteArrayLiteral("\":\r\n");
        if (arrayValue) {
            right.append(QByteArrayLiteral("[\r\n"));
            right.append(quote);
            right.append(QByteArrayLiteral("SECOND-SERIALIZED-SECRET"));
            right.append(quote);
            right.append(QByteArrayLiteral(",\r\n"));
            right.append(quote);
            right.append(QByteArrayLiteral("THIRD-SERIALIZED-SENTINEL"));
            right.append(quote);
            right.append(QByteArrayLiteral("]\r\n}\r\n"));
        } else {
            right.append(quote);
            right.append(QByteArrayLiteral("SECOND-SERIALIZED-SECRET"));
            right.append(quote);
            right.append(QByteArrayLiteral("\r\n}\r\n"));
        }
        const QByteArray raw = left + right;
        const SanitizedChunk leftState = sanitize(left);
        CHECK(leftState.streamState.pendingSecretKind
              == (arrayValue ? PendingSecretKind::Array
                             : PendingSecretKind::Scalar));
        CHECK(leftState.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(leftState.streamState.pendingSecretWhitespaceBytes
              == (arrayValue ? MaximumPendingSecretWhitespaceBytes : 0));
        const QByteArray splitSanitized = sanitizeAcrossSplit(raw, left.size());
        CHECK(!splitSanitized.contains("FIRST-SERIALIZED-SECRET"));
        CHECK(!splitSanitized.contains("SECOND-SERIALIZED-SECRET"));
        CHECK(!splitSanitized.contains("THIRD-SERIALIZED-SENTINEL"));
        const SanitizedChunk initialOffsetSanitized =
                sanitizeAfterInitialOffset(raw, left.size());
        CHECK(!initialOffsetSanitized.data.contains("SECOND-SERIALIZED-SECRET"));
        CHECK(!initialOffsetSanitized.data.contains(
                "THIRD-SERIALIZED-SENTINEL"));
    };
    checkTrailingSerializedPendingAfterEarlierKey(
            QByteArrayLiteral("token"), false);
    checkTrailingSerializedPendingAfterEarlierKey(
            QByteArrayLiteral("additional_secrets"), true);

    const auto checkMixedFormatTrailingPending = [&]
            (bool earlierSerialized, bool trailingSerialized,
             bool trailingArray, bool arrayStartsOnKeyLine) {
        const QByteArray quote = serializedQuote(1);
        const QByteArray trailingKey = trailingArray
                ? QByteArrayLiteral("additional_secrets")
                : QByteArrayLiteral("token");
        QByteArray left = QByteArrayLiteral("payload={");
        if (earlierSerialized) {
            left.append(quote);
            left.append(QByteArrayLiteral("password"));
            left.append(quote);
            left.append(QByteArrayLiteral(":"));
            left.append(quote);
            left.append(QByteArrayLiteral("FIRST-MIXED-SECRET"));
            left.append(quote);
        } else {
            left.append(QByteArrayLiteral("\"password\":\"FIRST-MIXED-SECRET\""));
        }
        left.append(QByteArrayLiteral(", "));
        if (trailingSerialized) {
            left.append(quote);
            left.append(trailingKey);
            left.append('\\');
        } else {
            left.append(trailingKey);
        }

        QByteArray right;
        if (trailingSerialized) {
            right.append('\"');
        }
        right.append(trailingArray && arrayStartsOnKeyLine
                     ? QByteArrayLiteral(": [\r\n")
                     : QByteArrayLiteral(":\r\n"));
        if (trailingArray) {
            if (!arrayStartsOnKeyLine) {
                right.append(QByteArrayLiteral("[\r\n"));
            }
            if (trailingSerialized) {
                right.append(quote);
            } else {
                right.append('\"');
            }
            right.append(QByteArrayLiteral("SECOND-MIXED-SECRET"));
            if (trailingSerialized) {
                right.append(quote);
            } else {
                right.append('\"');
            }
            right.append(QByteArrayLiteral(",\r\n"));
            if (trailingSerialized) {
                right.append(quote);
            } else {
                right.append('\"');
            }
            right.append(QByteArrayLiteral("THIRD-MIXED-SENTINEL"));
            if (trailingSerialized) {
                right.append(quote);
            } else {
                right.append('\"');
            }
            right.append(QByteArrayLiteral("]\r\n}\r\n"));
        } else {
            if (trailingSerialized) {
                right.append(quote);
            }
            right.append(QByteArrayLiteral("SECOND-MIXED-SECRET"));
            if (trailingSerialized) {
                right.append(quote);
            }
            right.append(QByteArrayLiteral("\r\n}\r\n"));
        }

        const QByteArray raw = left + right;
        const SanitizedChunk leftState = sanitize(left);
        CHECK(leftState.streamState.pendingSecretKind
              == (trailingArray ? PendingSecretKind::Array
                                : PendingSecretKind::Scalar));
        CHECK(leftState.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(leftState.streamState.pendingSecretWhitespaceBytes
              == (trailingArray && trailingSerialized
                          ? MaximumPendingSecretWhitespaceBytes : 0));
        const SanitizedChunk wholeSanitized = sanitize(raw);
        CHECK(!wholeSanitized.data.contains("FIRST-MIXED-SECRET"));
        CHECK(!wholeSanitized.data.contains("SECOND-MIXED-SECRET"));
        CHECK(!wholeSanitized.data.contains("THIRD-MIXED-SENTINEL"));
        CHECK(wholeSanitized.streamState.pendingSecretKind
              == PendingSecretKind::Array);
        CHECK(wholeSanitized.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(wholeSanitized.streamState.pendingSecretWhitespaceBytes
              == MaximumPendingSecretWhitespaceBytes);
        for (qsizetype split = 1; split < raw.size(); ++split) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            if (splitSanitized.contains("FIRST-MIXED-SECRET")
                || splitSanitized.contains("SECOND-MIXED-SECRET")
                || splitSanitized.contains("THIRD-MIXED-SENTINEL")
                || initialOffsetSanitized.data.contains("SECOND-MIXED-SECRET")
                || initialOffsetSanitized.data.contains(
                        "THIRD-MIXED-SENTINEL")) {
                QTextStream(stderr) << "mixed leak earlierSerialized="
                                    << earlierSerialized
                                    << " trailingSerialized="
                                    << trailingSerialized
                                    << " trailingArray=" << trailingArray
                                    << " arrayStartsOnKeyLine="
                                    << arrayStartsOnKeyLine
                                    << " split=" << split << Qt::endl;
            }
            CHECK(!splitSanitized.contains("FIRST-MIXED-SECRET"));
            CHECK(!splitSanitized.contains("SECOND-MIXED-SECRET"));
            CHECK(!splitSanitized.contains("THIRD-MIXED-SENTINEL"));
            CHECK(!initialOffsetSanitized.data.contains("SECOND-MIXED-SECRET"));
            CHECK(!initialOffsetSanitized.data.contains(
                    "THIRD-MIXED-SENTINEL"));
        }
    };
    for (const bool earlierSerialized : { false, true }) {
        for (const bool trailingSerialized : { false, true }) {
            checkMixedFormatTrailingPending(
                    earlierSerialized, trailingSerialized, false, false);
            checkMixedFormatTrailingPending(
                    earlierSerialized, trailingSerialized, true, false);
            checkMixedFormatTrailingPending(
                    earlierSerialized, trailingSerialized, true, true);
        }
    }

    const auto checkAmbiguousArrayWhitespace = [&](qsizetype whitespaceBytes) {
        const QByteArray quote = serializedQuote(1);
        QByteArray raw = QByteArrayLiteral("payload={") + quote
                + QByteArrayLiteral("password") + quote
                + QByteArrayLiteral(":") + quote
                + QByteArrayLiteral("FIRST-WHITESPACE-SECRET") + quote
                + QByteArrayLiteral(", additional_secrets:\r\n");
        const qsizetype whitespaceStart = raw.size();
        raw.append(QByteArray(whitespaceBytes, ' '));
        raw.append(QByteArrayLiteral(
                "[\r\n\"SECOND-WHITESPACE-SECRET\",\r\n"
                "\"THIRD-WHITESPACE-SENTINEL\"]\r\n}\r\n"));

        const SanitizedChunk whole = sanitize(raw);
        CHECK(!whole.data.contains("FIRST-WHITESPACE-SECRET"));
        CHECK(!whole.data.contains("SECOND-WHITESPACE-SECRET"));
        CHECK(!whole.data.contains("THIRD-WHITESPACE-SENTINEL"));
        CHECK(whole.streamState.pendingSecretKind == PendingSecretKind::Array);
        CHECK(whole.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(whole.streamState.pendingSecretWhitespaceBytes
              == MaximumPendingSecretWhitespaceBytes);

        ChunkContext markerContext;
        markerContext.streamState = whole.streamState;
        const SanitizedChunk markerContinuation = sanitize(
                QByteArrayLiteral("health=must-remain-private\r\n"),
                markerContext);
        CHECK(!markerContinuation.data.contains("health=must-remain-private"));
        CHECK(markerContinuation.streamState.pendingSecretKind
              == PendingSecretKind::Array);
        CHECK(markerContinuation.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(markerContinuation.streamState.pendingSecretWhitespaceBytes
              == MaximumPendingSecretWhitespaceBytes);

        QList<qsizetype> splitPositions {
            raw.indexOf("additional_secrets")
                    + qsizetype(sizeof("additional_secrets") - 1),
            whitespaceStart,
            whitespaceStart + 1,
            whitespaceStart + qMin<qsizetype>(255, whitespaceBytes),
            whitespaceStart + qMin<qsizetype>(256, whitespaceBytes),
            whitespaceStart + qMin<qsizetype>(257, whitespaceBytes),
            whitespaceStart + qMax<qsizetype>(0, whitespaceBytes - 1),
            whitespaceStart + whitespaceBytes
        };
        for (const qsizetype split : splitPositions) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            CHECK(!splitSanitized.contains("FIRST-WHITESPACE-SECRET"));
            CHECK(!splitSanitized.contains("SECOND-WHITESPACE-SECRET"));
            CHECK(!splitSanitized.contains("THIRD-WHITESPACE-SENTINEL"));
            CHECK(!initialOffsetSanitized.data.contains(
                    "SECOND-WHITESPACE-SECRET"));
            CHECK(!initialOffsetSanitized.data.contains(
                    "THIRD-WHITESPACE-SENTINEL"));
        }
    };
    checkAmbiguousArrayWhitespace(300);
    checkAmbiguousArrayWhitespace(
            MaximumPendingSecretWhitespaceBytes + 1);

    const auto checkEarlierScalarBeforeRawArray = [&]
            (bool serializedEarlier, bool closeArray) {
        const QByteArray earlierQuote = serializedEarlier
                ? serializedQuote(1) : QByteArrayLiteral("\"");
        QByteArray raw = QByteArrayLiteral("payload={") + earlierQuote
                + QByteArrayLiteral("password") + earlierQuote
                + QByteArrayLiteral(":") + earlierQuote
                + QByteArrayLiteral("OPEN-RAW-FIRST-SECRET") + earlierQuote
                + QByteArrayLiteral("}\r\nadditional_secrets: [\r\n")
                + QByteArrayLiteral("\"OPEN-RAW-ARRAY-SECRET\"\r\n");
        if (closeArray) {
            raw.append(QByteArrayLiteral("]\r\nhealth=closed-array-control\r\n"));
        }

        const SanitizedChunk whole = sanitize(raw);
        CHECK(!whole.data.contains("OPEN-RAW-FIRST-SECRET"));
        CHECK(!whole.data.contains("OPEN-RAW-ARRAY-SECRET"));
        CHECK(whole.streamState.secretArrayOpen == !closeArray);
        CHECK(whole.streamState.pendingSecretKind == PendingSecretKind::None);
        CHECK(whole.streamState.pendingSecretPhase == PendingSecretPhase::None);
        if (closeArray) {
            CHECK(whole.data.contains("health=closed-array-control"));
        }

        for (qsizetype split = 1; split < raw.size(); ++split) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            CHECK(!splitSanitized.contains("OPEN-RAW-FIRST-SECRET"));
            CHECK(!splitSanitized.contains("OPEN-RAW-ARRAY-SECRET"));
            CHECK(!initialOffsetSanitized.data.contains("OPEN-RAW-FIRST-SECRET"));
            CHECK(!initialOffsetSanitized.data.contains("OPEN-RAW-ARRAY-SECRET"));
            const bool privacyMarker =
                    initialOffsetSanitized.streamState.pendingSecretKind
                            == PendingSecretKind::Array
                    && initialOffsetSanitized.streamState.pendingSecretPhase
                            == PendingSecretPhase::AwaitingSeparator
                    && initialOffsetSanitized.streamState.pendingSecretWhitespaceBytes
                            == MaximumPendingSecretWhitespaceBytes;
            // An offset through ambiguous source syntax may conservatively
            // promote the stream to the persistent privacy marker. Otherwise
            // the ordinary raw-array state remains exact.
            CHECK(privacyMarker
                  || initialOffsetSanitized.streamState.secretArrayOpen
                          == !closeArray);
            CHECK(privacyMarker
                  || initialOffsetSanitized.streamState.pendingSecretKind
                          == PendingSecretKind::None);
            CHECK(privacyMarker
                  || initialOffsetSanitized.streamState.pendingSecretPhase
                          == PendingSecretPhase::None);
        }
    };
    checkEarlierScalarBeforeRawArray(false, false);
    checkEarlierScalarBeforeRawArray(false, true);
    checkEarlierScalarBeforeRawArray(true, false);
    checkEarlierScalarBeforeRawArray(true, true);

    const QByteArray serializedArrayQuote = serializedQuote(1);
    const QByteArray serializedArrayBeforeOpenRaw =
            QByteArrayLiteral("payload={") + serializedArrayQuote
            + QByteArrayLiteral("additional_secrets") + serializedArrayQuote
            + QByteArrayLiteral(":[") + serializedArrayQuote
            + QByteArrayLiteral("SERIALIZED-ARRAY-BEFORE-RAW-SECRET")
            + serializedArrayQuote
            + QByteArrayLiteral("]}\r\nadditional_secrets: [\r\n")
            + QByteArrayLiteral("\"OPEN-RAW-AFTER-SERIALIZED-ARRAY\"\r\n");
    const SanitizedChunk serializedArrayBeforeOpenRawWhole =
            sanitize(serializedArrayBeforeOpenRaw);
    CHECK(!serializedArrayBeforeOpenRawWhole.data.contains(
            "SERIALIZED-ARRAY-BEFORE-RAW-SECRET"));
    CHECK(!serializedArrayBeforeOpenRawWhole.data.contains(
            "OPEN-RAW-AFTER-SERIALIZED-ARRAY"));
    CHECK(!serializedArrayBeforeOpenRawWhole.streamState.secretArrayOpen);
    CHECK(serializedArrayBeforeOpenRawWhole.streamState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(serializedArrayBeforeOpenRawWhole.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(serializedArrayBeforeOpenRawWhole.streamState.pendingSecretWhitespaceBytes
          == MaximumPendingSecretWhitespaceBytes);
    for (qsizetype split = 1;
         split < serializedArrayBeforeOpenRaw.size(); ++split) {
        const QByteArray splitSanitized = sanitizeAcrossSplit(
                serializedArrayBeforeOpenRaw, split);
        const SanitizedChunk initialOffsetSanitized = sanitizeAfterInitialOffset(
                serializedArrayBeforeOpenRaw, split);
        CHECK(!splitSanitized.contains(
                "SERIALIZED-ARRAY-BEFORE-RAW-SECRET"));
        CHECK(!splitSanitized.contains(
                "OPEN-RAW-AFTER-SERIALIZED-ARRAY"));
        CHECK(!initialOffsetSanitized.data.contains(
                "SERIALIZED-ARRAY-BEFORE-RAW-SECRET"));
        CHECK(!initialOffsetSanitized.data.contains(
                "OPEN-RAW-AFTER-SERIALIZED-ARRAY"));
        CHECK(!(initialOffsetSanitized.streamState.secretArrayOpen
                && initialOffsetSanitized.streamState.pendingSecretPhase
                        != PendingSecretPhase::None));
    }

    const auto checkSingleCrossingAssignment = [&](bool serialized) {
        const QByteArray quote = serialized
                ? serializedQuote(1) : QByteArrayLiteral("\"");
        QByteArray raw = QByteArrayLiteral("health=before-single\r\npayload={")
                + quote + QByteArrayLiteral("password") + quote
                + QByteArrayLiteral(":\r\n") + quote
                + QByteArrayLiteral("SINGLE-CROSSING-SECRET") + quote
                + QByteArrayLiteral("\r\n}\r\nhealth=after-single\r\n");
        const qsizetype keyStart = raw.indexOf("password");
        const qsizetype separatorEnd = raw.indexOf(':', keyStart) + 1;
        for (qsizetype split = keyStart; split <= separatorEnd; ++split) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            CHECK(!splitSanitized.contains("SINGLE-CROSSING-SECRET"));
            CHECK(splitSanitized.contains("health=after-single"));
            CHECK(!initialOffsetSanitized.data.contains(
                    "SINGLE-CROSSING-SECRET"));
            CHECK(initialOffsetSanitized.data.contains("health=after-single"));
            CHECK(initialOffsetSanitized.streamState.pendingSecretKind
                  == PendingSecretKind::None);
            CHECK(initialOffsetSanitized.streamState.pendingSecretPhase
                  == PendingSecretPhase::None);
        }
    };
    checkSingleCrossingAssignment(false);
    checkSingleCrossingAssignment(true);

    const auto checkChainedCrossRecordAssignments = [&]
            (bool serialized, const QByteArray &lineBreak) {
        const QByteArray quote = serialized
                ? serializedQuote(1) : QByteArrayLiteral("");
        QByteArray raw = QByteArrayLiteral("health=before-chained") + lineBreak
                + quote + QByteArrayLiteral("password") + quote
                + QByteArrayLiteral(":") + lineBreak + QByteArrayLiteral(" ")
                + quote + QByteArrayLiteral("token") + quote
                + QByteArrayLiteral(":") + lineBreak + quote
                + QByteArrayLiteral("CHAINED-CROSS-RECORD-SECRET") + quote
                + lineBreak + QByteArrayLiteral("health=after-chained")
                + lineBreak;

        const SanitizedChunk whole = sanitize(raw);
        CHECK(!whole.data.contains("CHAINED-CROSS-RECORD-SECRET"));
        CHECK(whole.streamState.pendingSecretKind == PendingSecretKind::Array);
        CHECK(whole.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(whole.streamState.pendingSecretWhitespaceBytes
              == MaximumPendingSecretWhitespaceBytes);

        for (qsizetype split = 1; split < raw.size(); ++split) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            CHECK(!splitSanitized.contains("CHAINED-CROSS-RECORD-SECRET"));
            CHECK(!initialOffsetSanitized.data.contains(
                    "CHAINED-CROSS-RECORD-SECRET"));
        }
    };
    for (const bool serialized : { false, true }) {
        for (const QByteArray &lineBreak : {
                     QByteArrayLiteral("\n"), QByteArrayLiteral("\r\n"),
                     QByteArrayLiteral("\r") }) {
            checkChainedCrossRecordAssignments(serialized, lineBreak);
        }
    }

    const auto checkStructuredMultilineScalar = [&](bool serialized,
                                                      const QByteArray &lineBreak,
                                                      QByteArray firstLineValue,
                                                      QByteArray closingLine) {
        const QByteArray quote = serialized
                ? serializedQuote(1) : QByteArrayLiteral("\"");
        if (firstLineValue == QByteArrayLiteral("\"")) {
            firstLineValue = quote;
            closingLine = quote;
        }
        QByteArray raw = QByteArrayLiteral("health=before-structured")
                + lineBreak + quote + QByteArrayLiteral("password") + quote
                + QByteArrayLiteral(": ") + firstLineValue + lineBreak
                + QByteArrayLiteral("STRUCTURED-MULTILINE-SCALAR-SECRET")
                + lineBreak + closingLine + lineBreak
                + QByteArrayLiteral("health=after-structured") + lineBreak;

        const SanitizedChunk whole = sanitize(raw);
        CHECK(!whole.data.contains("STRUCTURED-MULTILINE-SCALAR-SECRET"));
        CHECK(whole.streamState.pendingSecretKind == PendingSecretKind::Array);
        CHECK(whole.streamState.pendingSecretPhase
              == PendingSecretPhase::AwaitingSeparator);
        CHECK(whole.streamState.pendingSecretWhitespaceBytes
              == MaximumPendingSecretWhitespaceBytes);
        for (qsizetype split = 1; split < raw.size(); ++split) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            CHECK(!splitSanitized.contains(
                    "STRUCTURED-MULTILINE-SCALAR-SECRET"));
            CHECK(!initialOffsetSanitized.data.contains(
                    "STRUCTURED-MULTILINE-SCALAR-SECRET"));
        }
    };
    const QList<QByteArray> structuredScalarFirstLines {
        QByteArrayLiteral("["),
        QByteArrayLiteral("{"),
        QByteArrayLiteral("|"),
        QByteArrayLiteral(">"),
        QByteArrayLiteral("\""),
        QByteArrayLiteral("prefix-\\")
    };
    const QList<QByteArray> structuredScalarClosingLines {
        QByteArrayLiteral("]"),
        QByteArrayLiteral("}"),
        {},
        {},
        QByteArrayLiteral("\""),
        {}
    };
    for (const bool serialized : { false, true }) {
        for (const QByteArray &lineBreak : {
                     QByteArrayLiteral("\n"), QByteArrayLiteral("\r\n"),
                     QByteArrayLiteral("\r") }) {
            for (qsizetype fixture = 0;
                 fixture < structuredScalarFirstLines.size(); ++fixture) {
                checkStructuredMultilineScalar(
                        serialized, lineBreak,
                        structuredScalarFirstLines.at(fixture),
                        structuredScalarClosingLines.at(fixture));
            }
        }
    }

    const auto checkEvenBackslashNonContinuation = [&]
            (bool serialized, const QByteArray &lineBreak) {
        const QByteArray quote = serialized
                ? serializedQuote(1) : QByteArrayLiteral("\"");
        const QByteArray diagnostic = QByteArrayLiteral(
                "EVEN-BACKSLASH-DIAGNOSTIC");
        const QByteArray health = QByteArrayLiteral(
                "health=after-even-backslash");
        const QByteArray raw = QByteArrayLiteral("health=before-even-backslash")
                + lineBreak + quote + QByteArrayLiteral("password") + quote
                + QByteArrayLiteral(": prefix-\\\\") + lineBreak
                + diagnostic + lineBreak + health + lineBreak;
        const qsizetype diagnosticStart = raw.indexOf(diagnostic);
        const qsizetype slashRunStart = raw.indexOf("prefix-")
                + qsizetype(sizeof("prefix-") - 1);

        const SanitizedChunk whole = sanitize(raw);
        CHECK(whole.data.contains(diagnostic));
        CHECK(whole.data.contains(health));
        CHECK(whole.streamState.pendingSecretKind == PendingSecretKind::None);
        CHECK(whole.streamState.pendingSecretPhase == PendingSecretPhase::None);
        const QList<qsizetype> unambiguousSplits {
            raw.indexOf("prefix-"),
            slashRunStart,
            slashRunStart + 2,
            diagnosticStart
        };
        for (const qsizetype split : unambiguousSplits) {
            const QByteArray splitSanitized = sanitizeAcrossSplit(raw, split);
            const SanitizedChunk initialOffsetSanitized =
                    sanitizeAfterInitialOffset(raw, split);
            CHECK(splitSanitized.contains(diagnostic));
            CHECK(splitSanitized.contains(health));
            CHECK(initialOffsetSanitized.data.contains(diagnostic));
            CHECK(initialOffsetSanitized.data.contains(health));
            const bool privacyMarker =
                    initialOffsetSanitized.streamState.pendingSecretKind
                            == PendingSecretKind::Array
                    && initialOffsetSanitized.streamState.pendingSecretPhase
                            == PendingSecretPhase::AwaitingSeparator
                    && initialOffsetSanitized.streamState.pendingSecretWhitespaceBytes
                            == MaximumPendingSecretWhitespaceBytes;
            CHECK(!privacyMarker);
        }

        const qsizetype ambiguousSlashSplit = slashRunStart + 1;
        const SanitizedChunk ambiguousInitialOffset =
                sanitizeAfterInitialOffset(raw, ambiguousSlashSplit);
        const bool ambiguousPrivacyMarker =
                ambiguousInitialOffset.streamState.pendingSecretKind
                        == PendingSecretKind::Array
                && ambiguousInitialOffset.streamState.pendingSecretPhase
                        == PendingSecretPhase::AwaitingSeparator
                && ambiguousInitialOffset.streamState.pendingSecretWhitespaceBytes
                        == MaximumPendingSecretWhitespaceBytes;
        // A chunk boundary can hide the parity of a terminal slash run. Either
        // preserve the even-run diagnostic or fail closed with the marker.
        CHECK(ambiguousPrivacyMarker
              || (ambiguousInitialOffset.data.contains(diagnostic)
                  && ambiguousInitialOffset.data.contains(health)));
    };
    for (const bool serialized : { false, true }) {
        for (const QByteArray &lineBreak : {
                     QByteArrayLiteral("\n"), QByteArrayLiteral("\r\n"),
                     QByteArrayLiteral("\r") }) {
            checkEvenBackslashNonContinuation(serialized, lineBreak);
        }
    }

    const QByteArray serializedDensityRecord = QByteArrayLiteral("payload={")
            + serializedQuote(1) + QByteArrayLiteral("password")
            + serializedQuote(1) + QByteArrayLiteral(":")
            + serializedQuote(1)
            + QByteArrayLiteral("DENSITY-SERIALIZED-SECRET")
            + serializedQuote(1) + QByteArrayLiteral("}\n");
    QByteArray nearCapSerializedDensity;
    nearCapSerializedDensity.reserve(MaximumInputBytes - 1024);
    while (nearCapSerializedDensity.size() + serializedDensityRecord.size()
           <= MaximumInputBytes - 1024) {
        nearCapSerializedDensity.append(serializedDensityRecord);
    }
    const SanitizedChunk sanitizedNearCapDensity =
            sanitize(nearCapSerializedDensity);
    CHECK(!sanitizedNearCapDensity.data.contains(
            "DENSITY-SERIALIZED-SECRET"));
    CHECK(!sanitizedNearCapDensity.privateKeyBlockOpen);
    CHECK(sanitizedNearCapDensity.data.size() <= MaximumOutputBytes);

    const QByteArray privateBlockDensityRecord = QByteArrayLiteral(
            "-----BEGIN PRIVATE KEY-----\n"
            "DENSITY-PRIVATE-BODY\n"
            "-----END PRIVATE KEY-----\n");
    QByteArray oneMiBPrivateBlockDensity;
    oneMiBPrivateBlockDensity.reserve(1024 * 1024);
    while (oneMiBPrivateBlockDensity.size() + privateBlockDensityRecord.size()
           <= 1024 * 1024) {
        oneMiBPrivateBlockDensity.append(privateBlockDensityRecord);
    }
    const SanitizedChunk sanitizedPrivateBlockDensity =
            sanitize(oneMiBPrivateBlockDensity);
    CHECK(!sanitizedPrivateBlockDensity.data.contains("DENSITY-PRIVATE-BODY"));
    CHECK(!sanitizedPrivateBlockDensity.privateKeyBlockOpen);
    CHECK(sanitizedPrivateBlockDensity.data.contains("[REDACTED PRIVATE KEY]"));

    QByteArray markerPrefix = QByteArrayLiteral("payload={");
    markerPrefix.append(serializedQuote(1));
    markerPrefix.append(QByteArrayLiteral("additional_secrets"));
    markerPrefix.append(serializedQuote(1));
    markerPrefix.append(QByteArrayLiteral(":\r\n[\r\n"));
    markerPrefix.append(serializedQuote(1));
    markerPrefix.append(QByteArrayLiteral("MARKER-FIRST-SECRET"));
    markerPrefix.append(serializedQuote(1));
    markerPrefix.append(QByteArrayLiteral(",\r\n"));
    const SanitizedChunk markerEstablished = sanitize(markerPrefix);
    CHECK(markerEstablished.streamState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(markerEstablished.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(markerEstablished.streamState.pendingSecretWhitespaceBytes
          == MaximumPendingSecretWhitespaceBytes);
    const QByteArray markerCrossingLeft = QByteArrayLiteral("passwo");
    const QByteArray markerCrossingRight = QByteArrayLiteral(
            "rd:\r\nMARKER-SECOND-SECRET\r\n");
    const StreamBoundary markerDominatedBoundary = inspectStreamBoundary(
            markerCrossingLeft,
            markerCrossingRight,
            markerEstablished.streamState);
    CHECK(markerDominatedBoundary.pendingSecretKind == PendingSecretKind::None);
    CHECK(markerDominatedBoundary.pendingSecretPhase == PendingSecretPhase::None);
    ChunkContext markerDominanceContext;
    markerDominanceContext.streamState = markerEstablished.streamState;
    markerDominanceContext.boundaryPendingSecretKind = PendingSecretKind::Scalar;
    markerDominanceContext.boundaryPendingSecretPhase =
            PendingSecretPhase::RedactingValue;
    markerDominanceContext.boundaryPendingSecretCharacters = 2;
    const SanitizedChunk markerDominance = sanitize(
            markerCrossingRight, markerDominanceContext);
    CHECK(!markerDominance.data.contains("MARKER-SECOND-SECRET"));
    CHECK(markerDominance.streamState.pendingSecretKind
          == PendingSecretKind::Array);
    CHECK(markerDominance.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(markerDominance.streamState.pendingSecretWhitespaceBytes
          == MaximumPendingSecretWhitespaceBytes);
    ChunkContext markerThirdContext;
    markerThirdContext.streamState = markerDominance.streamState;
    const SanitizedChunk markerThird = sanitize(QByteArrayLiteral(
            "MARKER-THIRD-SENTINEL\r\nhealth=must-also-be-redacted\r\n"),
            markerThirdContext);
    CHECK(!markerThird.data.contains("MARKER-THIRD-SENTINEL"));
    CHECK(!markerThird.data.contains("health=must-also-be-redacted"));
    CHECK(markerThird.streamState.pendingSecretKind == PendingSecretKind::Array);
    CHECK(markerThird.streamState.pendingSecretPhase
          == PendingSecretPhase::AwaitingSeparator);
    CHECK(markerThird.streamState.pendingSecretWhitespaceBytes
          == MaximumPendingSecretWhitespaceBytes);

    const QByteArray oversized(MaximumInputBytes + 1, 'x');
    const SanitizedChunk bounded = sanitize(oversized);
    CHECK(bounded.data.size() < 1024);
    CHECK(bounded.privateKeyBlockOpen);

    const QString uploaderPath = QFileInfo(QString::fromUtf8(__FILE__)).absoluteDir().filePath(
            QStringLiteral("../../core/controllers/remoteLogUploader.cpp"));
    QFile uploaderSourceFile(uploaderPath);
    CHECK(uploaderSourceFile.open(QIODevice::ReadOnly));
    const QByteArray uploaderSource = uploaderSourceFile.readAll();
    CHECK(uploaderSource.contains(
            "reply->rawHeader(\"X-Amnezia-Batch-Accepted\") == QByteArrayLiteral(\"1\")"));
    CHECK(uploaderSource.contains(
            "reply->rawHeader(\"X-Amnezia-Batch-Id\") == batchId"));
    CHECK(uploaderSource.contains("constexpr int streamStateVersion = 2;"));
    CHECK(uploaderSource.contains("streamStatePendingKind"));
    CHECK(uploaderSource.contains("streamStatePendingPhase"));
    CHECK(uploaderSource.contains("streamStatePendingWhitespaceBytes"));
    CHECK(uploaderSource.contains("const bool ok = httpOk && receiptAccepted;"));
    CHECK(uploaderSource.indexOf("const bool ok = httpOk && receiptAccepted;")
          < uploaderSource.indexOf("persistCursor(payload.offsetKey"));

    return runner.finish();
}
