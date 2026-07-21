#include "remoteLogSanitizer.h"

#include <QRegularExpression>
#include <QString>

namespace amnezia::remoteLogSanitizer
{
    namespace
    {
        const QString redactedValue = QStringLiteral("***");
        const QString redactedPrivateKey = QStringLiteral("[REDACTED PRIVATE KEY]");
        const QString redactedPartialRecord = QStringLiteral("[REDACTED PARTIAL LOG RECORD]");
        const QByteArray redactedChunk = QByteArrayLiteral("[REDACTED LOG CHUNK]\n");

        qsizetype nextRecordSeparatorStart(const QString &text, qsizetype from = 0)
        {
            for (qsizetype cursor = qMax<qsizetype>(0, from);
                 cursor < text.size(); ++cursor) {
                const QChar character = text.at(cursor);
                if (character == QLatin1Char('\r')
                    || character == QLatin1Char('\n')) {
                    return cursor;
                }
            }
            return -1;
        }

        qsizetype recordSeparatorEnd(const QString &text, qsizetype start)
        {
            if (start < 0 || start >= text.size()) {
                return text.size();
            }
            return text.at(start) == QLatin1Char('\r')
                            && start + 1 < text.size()
                            && text.at(start + 1) == QLatin1Char('\n')
                    ? start + 2 : start + 1;
        }

        qsizetype lastRecordSeparatorEnd(const QString &text)
        {
            for (qsizetype cursor = text.size(); cursor > 0; --cursor) {
                const QChar character = text.at(cursor - 1);
                if (character == QLatin1Char('\r')
                    || character == QLatin1Char('\n')) {
                    return recordSeparatorEnd(text, cursor - 1);
                }
            }
            return 0;
        }

        // Internal subjects are valid UTF-16 produced by QString::fromUtf8,
        // and loop cursors come from ASCII marker/newline positions. Skipping
        // repeated validation keeps dense marker scans linear; do not reuse
        // this option for an arbitrary externally supplied QString.
        constexpr auto trustedUtf16SubjectMatchOption =
                QRegularExpression::DontCheckSubjectStringMatchOption;

        const QRegularExpression &privateKeyBeginExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(-----BEGIN[ \t]+[A-Z0-9 -]{0,64}PRIVATE[ \t]+KEY-----)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &privateKeyEndExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(-----END[ \t]+[A-Z0-9 -]{0,64}PRIVATE[ \t]+KEY-----)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &openVpnStaticKeyBeginExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(-----BEGIN[ \t]+OPENVPN[ \t]+STATIC[ \t]+KEY[ \t]+V1-----)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &openVpnStaticKeyEndExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(-----END[ \t]+OPENVPN[ \t]+STATIC[ \t]+KEY[ \t]+V1-----)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &tlsAuthBeginExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(<[ \t]*tls-auth[ \t]*>)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &tlsAuthEndExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(<[ \t]*/[ \t]*tls-auth[ \t]*>)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &tlsCryptBeginExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(<[ \t]*tls-crypt(?:-v2)?[ \t]*>)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &tlsCryptEndExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(<[ \t]*/[ \t]*tls-crypt(?:-v2)?[ \t]*>)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QString &secretArrayKeyPattern()
        {
            static const QString pattern = QStringLiteral(
                    R"re((?:mtproxy[_-]?additional[_-]?secrets|telemt[_-]?additional[_-]?secrets|additional[_-]?secrets))re");
            return pattern;
        }

        const QString &scalarSecretKeyPattern()
        {
            static const QString pattern = QStringLiteral(
                    R"re((?:x-amnezia-(?:log-token|installation-id)|clientlogstoken|remote[_-]?log[_-]?installation[_-]?id|installation[_-]?(?:uuid|id)|client[_-]?private[_-]?key|client[_-]?priv[_-]?key|server[_-]?private[_-]?key|server[_-]?priv[_-]?key|private[_-]?key|pre[_-]?shared[_-]?key|preshared[_-]?key|psk[_-]?key|(?:mtproxy|telemt)[_-]?secret|(?:aes|vpn)[_-]?key|aes[_-]?(?:iv|salt)|tls[_-]?auth|xhttp[_-]?(?:session|seq|uplink[_-]?data)[_-]?key|xpadding[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?token|log[_-]?token|client[_-]?secret|api[_-]?key|proxy[_-]?authorization|authorization|set[_-]?cookie|cookie|password|passwd|pwd|passphrase|pass|secret|token))re");
            return pattern;
        }

        const QString &secretKeyPattern()
        {
            static const QString pattern = QStringLiteral("(?:")
                    + secretArrayKeyPattern() + QLatin1Char('|')
                    + scalarSecretKeyPattern() + QLatin1Char(')');
            return pattern;
        }

        QString serializedQuotedKeyPattern(const QString &keyPattern)
        {
            // qDebug/QWarning escape quotes when a QString contains serialized
            // JSON. Requiring the first slash and a possessive run keeps the
            // unbounded repeated-serialization depths linear to recognize.
            return QStringLiteral(
                           R"re((?<![A-Z0-9_-])(?<!\\)\\++["'])re")
                    + keyPattern
                    + QStringLiteral(R"re(\\++["'])re");
        }

        const QRegularExpression &secretArrayStartExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral(R"re(((?<![A-Z0-9_-])["']?)re")
                            + secretArrayKeyPattern()
                            + QStringLiteral(R"re(["']?\s*[:=]\s*)\[)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &pendingSeparatorExpression(PendingSecretKind kind)
        {
            static const QRegularExpression scalarExpression(
                    QStringLiteral(R"re((?im)(?<![A-Z0-9_-])["']?)re")
                            + scalarSecretKeyPattern()
                            + QStringLiteral(R"re(["']?(\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    QStringLiteral(R"re((?im)(?<![A-Z0-9_-])["']?)re")
                            + secretArrayKeyPattern()
                            + QStringLiteral(R"re(["']?(\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &pendingSerializedSeparatorExpression(
                PendingSecretKind kind)
        {
            static const QRegularExpression scalarExpression(
                    serializedQuotedKeyPattern(scalarSecretKeyPattern())
                            + QStringLiteral(R"re((\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    serializedQuotedKeyPattern(secretArrayKeyPattern())
                            + QStringLiteral(R"re((\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array
                    ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &pendingSerializedSlashRunExpression(
                PendingSecretKind kind)
        {
            // A serialized closing quote can contain an arbitrarily long slash
            // run. Persist the key as soon as a source chunk ends inside that
            // run; a fixed-size lookbehind cannot reconstruct the whole key on
            // the next chunk.
            static const QRegularExpression scalarExpression(
                    QStringLiteral(
                            R"re((?<![A-Z0-9_-])(?<!\\)\\++["'])re")
                            + scalarSecretKeyPattern()
                            + QStringLiteral(R"re(\\++\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    QStringLiteral(
                            R"re((?<![A-Z0-9_-])(?<!\\)\\++["'])re")
                            + secretArrayKeyPattern()
                            + QStringLiteral(R"re(\\++\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array
                    ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &pendingValueExpression(PendingSecretKind kind)
        {
            static const QRegularExpression scalarExpression(
                    QStringLiteral(R"re((?<![A-Z0-9_-])["']?)re")
                            + scalarSecretKeyPattern()
                            + QStringLiteral(R"re(["']?\s*[:=](\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    QStringLiteral(R"re((?<![A-Z0-9_-])["']?)re")
                            + secretArrayKeyPattern()
                            + QStringLiteral(R"re(["']?\s*[:=](\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &pendingSerializedValueExpression(
                PendingSecretKind kind)
        {
            static const QRegularExpression scalarExpression(
                    serializedQuotedKeyPattern(scalarSecretKeyPattern())
                            + QStringLiteral(R"re(\s*[:=](\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    serializedQuotedKeyPattern(secretArrayKeyPattern())
                            + QStringLiteral(R"re(\s*[:=](\s*)\z)re"),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array
                    ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &serializedBoundarySecretKeyExpression(
                PendingSecretKind kind)
        {
            static const QRegularExpression scalarExpression(
                    serializedQuotedKeyPattern(scalarSecretKeyPattern()),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    serializedQuotedKeyPattern(secretArrayKeyPattern()),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array
                    ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &serializedKeyWithSeparatorExpression(
                PendingSecretKind kind)
        {
            static const QRegularExpression scalarExpression(
                    serializedQuotedKeyPattern(scalarSecretKeyPattern())
                            + QStringLiteral(R"re(\s*[:=])re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    serializedQuotedKeyPattern(secretArrayKeyPattern())
                            + QStringLiteral(R"re(\s*[:=])re"),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array
                    ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &allSerializedKeysWithSeparatorExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral("(?<serializedArray>")
                            + serializedKeyWithSeparatorExpression(
                                      PendingSecretKind::Array).pattern()
                            + QStringLiteral(")|(?<serializedScalar>")
                            + serializedKeyWithSeparatorExpression(
                                      PendingSecretKind::Scalar).pattern()
                            + QLatin1Char(')'),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &allSecretAssignmentsExpression()
        {
            // This preflight pattern deliberately recognizes assignment syntax
            // only. Bare diagnostic words such as "password required" must not
            // turn the stream into the permanent privacy state.
            static const QRegularExpression expression(
                    QStringLiteral("(?<serializedArrayAssignment>")
                            + serializedQuotedKeyPattern(secretArrayKeyPattern())
                            + QStringLiteral(
                                      R"re(\s*+[:=](?<serializedArrayValueWhitespace>\s*+))re")
                            + QStringLiteral(")|(?<serializedScalarAssignment>")
                            + serializedQuotedKeyPattern(scalarSecretKeyPattern())
                            + QStringLiteral(
                                      R"re(\s*+[:=](?<serializedScalarValueWhitespace>\s*+))re")
                            + QStringLiteral(")|(?<rawArrayAssignment>(?<![A-Z0-9_-])[\"']?")
                            + secretArrayKeyPattern()
                            + QStringLiteral(
                                      R"re(["']?\s*+[:=](?<rawArrayValueWhitespace>\s*+)))re")
                            + QStringLiteral("|(?<rawScalarAssignment>(?<![A-Z0-9_-])[\"']?")
                            + scalarSecretKeyPattern()
                            + QStringLiteral(
                                      R"re(["']?\s*+[:=](?<rawScalarValueWhitespace>\s*+)))re"),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        const QRegularExpression &boundarySecretKeyExpression(PendingSecretKind kind)
        {
            static const QRegularExpression scalarExpression(
                    QStringLiteral(R"re((?:(?<![A-Z0-9_-])(["']))re")
                            + scalarSecretKeyPattern()
                            + QStringLiteral(R"re(\1|(?<![A-Z0-9_-]))re")
                            + scalarSecretKeyPattern()
                            + QStringLiteral(R"re((?![A-Z0-9_-])))re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression arrayExpression(
                    QStringLiteral(R"re((?:(?<![A-Z0-9_-])(["']))re")
                            + secretArrayKeyPattern()
                            + QStringLiteral(R"re(\1|(?<![A-Z0-9_-]))re")
                            + secretArrayKeyPattern()
                            + QStringLiteral(R"re((?![A-Z0-9_-])))re"),
                    QRegularExpression::CaseInsensitiveOption);
            return kind == PendingSecretKind::Array ? arrayExpression : scalarExpression;
        }

        const QRegularExpression &blockBeginExpression(SecretBlockKind kind)
        {
            switch (kind) {
            case SecretBlockKind::PrivateKey: return privateKeyBeginExpression();
            case SecretBlockKind::OpenVpnStaticKey: return openVpnStaticKeyBeginExpression();
            case SecretBlockKind::TlsAuth: return tlsAuthBeginExpression();
            case SecretBlockKind::TlsCrypt: return tlsCryptBeginExpression();
            case SecretBlockKind::None: break;
            }
            return privateKeyBeginExpression();
        }

        const QRegularExpression &blockEndExpression(SecretBlockKind kind)
        {
            switch (kind) {
            case SecretBlockKind::PrivateKey: return privateKeyEndExpression();
            case SecretBlockKind::OpenVpnStaticKey: return openVpnStaticKeyEndExpression();
            case SecretBlockKind::TlsAuth: return tlsAuthEndExpression();
            case SecretBlockKind::TlsCrypt: return tlsCryptEndExpression();
            case SecretBlockKind::None: break;
            }
            return privateKeyEndExpression();
        }

        const QRegularExpression &allBlockBeginExpression()
        {
            static const QRegularExpression expression(
                    QStringLiteral("(?<privateKeyBlock>")
                            + privateKeyBeginExpression().pattern()
                            + QStringLiteral(")|(?<openVpnStaticKeyBlock>")
                            + openVpnStaticKeyBeginExpression().pattern()
                            + QStringLiteral(")|(?<tlsAuthBlock>")
                            + tlsAuthBeginExpression().pattern()
                            + QStringLiteral(")|(?<tlsCryptBlock>")
                            + tlsCryptBeginExpression().pattern()
                            + QLatin1Char(')'),
                    QRegularExpression::CaseInsensitiveOption);
            return expression;
        }

        bool patternsAreValid()
        {
            return privateKeyBeginExpression().isValid() && privateKeyEndExpression().isValid()
                    && openVpnStaticKeyBeginExpression().isValid()
                    && openVpnStaticKeyEndExpression().isValid()
                    && tlsAuthBeginExpression().isValid() && tlsAuthEndExpression().isValid()
                    && tlsCryptBeginExpression().isValid() && tlsCryptEndExpression().isValid()
                    && secretArrayStartExpression().isValid()
                    && pendingSeparatorExpression(PendingSecretKind::Scalar).isValid()
                    && pendingSeparatorExpression(PendingSecretKind::Array).isValid()
                    && pendingSerializedSeparatorExpression(
                               PendingSecretKind::Scalar).isValid()
                    && pendingSerializedSeparatorExpression(
                               PendingSecretKind::Array).isValid()
                    && pendingSerializedSlashRunExpression(
                               PendingSecretKind::Scalar).isValid()
                    && pendingSerializedSlashRunExpression(
                               PendingSecretKind::Array).isValid()
                    && pendingValueExpression(PendingSecretKind::Scalar).isValid()
                    && pendingValueExpression(PendingSecretKind::Array).isValid()
                    && pendingSerializedValueExpression(
                               PendingSecretKind::Scalar).isValid()
                    && pendingSerializedValueExpression(
                               PendingSecretKind::Array).isValid()
                    && boundarySecretKeyExpression(PendingSecretKind::Scalar).isValid()
                    && boundarySecretKeyExpression(PendingSecretKind::Array).isValid()
                    && serializedBoundarySecretKeyExpression(
                               PendingSecretKind::Scalar).isValid()
                    && serializedBoundarySecretKeyExpression(
                               PendingSecretKind::Array).isValid()
                    && serializedKeyWithSeparatorExpression(
                               PendingSecretKind::Scalar).isValid()
                    && serializedKeyWithSeparatorExpression(
                               PendingSecretKind::Array).isValid()
                    && allSerializedKeysWithSeparatorExpression().isValid()
                    && allSecretAssignmentsExpression().isValid()
                    && allBlockBeginExpression().isValid();
        }

        bool scalarValueNeedsPermanentPrivacyMarker(
                const QString &text, qsizetype valueStart,
                qsizetype knownRecordEnd = -1)
        {
            if (valueStart < 0 || valueStart >= text.size()) {
                return false;
            }

            const QChar first = text.at(valueStart);
            if (first == QLatin1Char('[') || first == QLatin1Char('{')
                || first == QLatin1Char('|') || first == QLatin1Char('>')) {
                return true;
            }

            qsizetype recordEnd = knownRecordEnd;
            if (recordEnd < 0) {
                const qsizetype separator = nextRecordSeparatorStart(
                        text, valueStart);
                recordEnd = separator < 0 ? text.size() : separator;
            }
            if (recordEnd > valueStart
                && text.at(recordEnd - 1) == QLatin1Char('\r')) {
                --recordEnd;
            }

            qsizetype openingSlashCount = 0;
            qsizetype openingQuote = valueStart;
            while (openingQuote < recordEnd
                   && text.at(openingQuote) == QLatin1Char('\\')) {
                ++openingSlashCount;
                ++openingQuote;
            }
            if (openingQuote < recordEnd
                && (text.at(openingQuote) == QLatin1Char('"')
                    || text.at(openingQuote) == QLatin1Char('\''))) {
                const QChar quote = text.at(openingQuote);
                bool closed = false;
                qsizetype cursor = openingQuote + 1;
                while (cursor < recordEnd) {
                    if (text.at(cursor) == quote && openingSlashCount == 0) {
                        closed = true;
                        break;
                    }
                    if (text.at(cursor) != QLatin1Char('\\')) {
                        ++cursor;
                        continue;
                    }
                    const qsizetype slashStart = cursor;
                    while (cursor < recordEnd
                           && text.at(cursor) == QLatin1Char('\\')) {
                        ++cursor;
                    }
                    if (cursor < recordEnd && text.at(cursor) == quote) {
                        const qsizetype slashCount = cursor - slashStart;
                        if ((openingSlashCount == 0 && slashCount % 2 == 0)
                            || (openingSlashCount > 0
                                && slashCount == openingSlashCount)) {
                            closed = true;
                            break;
                        }
                    }
                    if (cursor < recordEnd) {
                        ++cursor;
                    }
                }
                if (!closed) {
                    return true;
                }
                // A closed quoted scalar has an exact value boundary. Any
                // later slash on the same record belongs to following syntax,
                // not to this credential's continuation.
                return false;
            }

            while (recordEnd > valueStart
                   && (text.at(recordEnd - 1) == QLatin1Char(' ')
                       || text.at(recordEnd - 1) == QLatin1Char('\t'))) {
                --recordEnd;
            }
            qsizetype trailingSlashCount = 0;
            while (recordEnd > valueStart
                   && text.at(recordEnd - 1) == QLatin1Char('\\')) {
                --recordEnd;
                ++trailingSlashCount;
            }
            return trailingSlashCount % 2 == 1;
        }

        bool hasAmbiguousSensitiveAssignments(
                const QString &text,
                bool pendingSecretActive,
                qsizetype boundaryPendingCharacters,
                bool endsInsideRecord,
                bool &trailingPartialScalarValue)
        {
            if (!allSecretAssignmentsExpression().isValid()) {
                return true;
            }

            qsizetype recordEnd = nextRecordSeparatorStart(text);
            qsizetype valueRecordEnd = recordEnd;
            qsizetype scalarConsumeEnd = -1;
            int assignmentsInRecord = 0;
            QRegularExpressionMatchIterator matches =
                    allSecretAssignmentsExpression().globalMatch(
                            text, 0, QRegularExpression::NormalMatch,
                            trustedUtf16SubjectMatchOption);
            while (matches.hasNext()) {
                const QRegularExpressionMatch match = matches.next();
                const qsizetype assignmentStart = match.capturedStart();
                while (recordEnd >= 0 && assignmentStart > recordEnd) {
                    assignmentsInRecord = 0;
                    recordEnd = nextRecordSeparatorStart(
                            text, recordSeparatorEnd(text, recordEnd));
                }

                ++assignmentsInRecord;
                // A boundary match can be rediscovered from the current-subject
                // start. Only a candidate after its consumed prefix is another
                // assignment and therefore ambiguous.
                const bool sameCrossingAssignment = boundaryPendingCharacters > 0
                        && assignmentStart < boundaryPendingCharacters;
                const bool serializedArray = match.capturedStart(
                                QStringLiteral("serializedArrayAssignment")) >= 0;
                const bool rawArray = match.capturedStart(
                                QStringLiteral("rawArrayAssignment")) >= 0;
                QString valueWhitespace;
                for (const QString &captureName : {
                             QStringLiteral("serializedArrayValueWhitespace"),
                             QStringLiteral("serializedScalarValueWhitespace"),
                             QStringLiteral("rawArrayValueWhitespace"),
                             QStringLiteral("rawScalarValueWhitespace") }) {
                    if (match.capturedStart(captureName) >= 0) {
                        valueWhitespace = match.captured(captureName);
                        break;
                    }
                }
                const bool valueStartsOnLaterRecord =
                        valueWhitespace.contains(QLatin1Char('\n'))
                        || valueWhitespace.contains(QLatin1Char('\r'));
                while (valueRecordEnd >= 0
                       && match.capturedEnd() > valueRecordEnd) {
                    valueRecordEnd = nextRecordSeparatorStart(
                            text, recordSeparatorEnd(text, valueRecordEnd));
                }
                const qsizetype currentValueRecordEnd = valueRecordEnd < 0
                        ? text.size()
                        : recordSeparatorEnd(text, valueRecordEnd);
                const qsizetype currentValueRecordContentEnd = valueRecordEnd < 0
                        ? text.size() : valueRecordEnd;
                if (!serializedArray && !rawArray
                    && scalarValueNeedsPermanentPrivacyMarker(
                            text, match.capturedEnd(),
                            currentValueRecordContentEnd)) {
                    return true;
                }
                const bool consumedByEarlierScalar = scalarConsumeEnd >= 0
                        && assignmentStart < scalarConsumeEnd;
                // Once an earlier assignment can consume this record, safely
                // reconstructing an array's nested/quoted extent would require
                // a second parser. Prefer the persisted privacy marker for this
                // rare multi-assignment shape; single array assignments keep the
                // normal stateful array parser and diagnostic preservation.
                const bool arrayNeedsConservativeShield =
                        serializedArray || rawArray;
                const bool extendsEarlierScalarConsume =
                        consumedByEarlierScalar
                        && (arrayNeedsConservativeShield
                            || currentValueRecordEnd > scalarConsumeEnd);
                if (endsInsideRecord && !serializedArray && !rawArray
                    && match.capturedEnd() < text.size()
                    && currentValueRecordEnd == text.size()) {
                    trailingPartialScalarValue = true;
                }
                if (extendsEarlierScalarConsume
                    || ((valueStartsOnLaterRecord || arrayNeedsConservativeShield)
                        && (assignmentsInRecord >= 2
                            || (pendingSecretActive
                                && !sameCrossingAssignment)))) {
                    return true;
                }
                if (!serializedArray && !rawArray) {
                    scalarConsumeEnd = qMax(
                            scalarConsumeEnd, currentValueRecordEnd);
                }
            }
            return false;
        }

        struct BlockMatch
        {
            SecretBlockKind kind = SecretBlockKind::None;
            QRegularExpressionMatch match;
        };

        BlockMatch nextBlockBegin(const QString &text, qsizetype cursor)
        {
            BlockMatch result;
            result.match = allBlockBeginExpression().match(
                    text, cursor, QRegularExpression::NormalMatch,
                    trustedUtf16SubjectMatchOption);
            if (!result.match.hasMatch()) {
                return result;
            }
            if (result.match.capturedStart(QStringLiteral("privateKeyBlock")) >= 0) {
                result.kind = SecretBlockKind::PrivateKey;
            } else if (result.match.capturedStart(
                               QStringLiteral("openVpnStaticKeyBlock")) >= 0) {
                result.kind = SecretBlockKind::OpenVpnStaticKey;
            } else if (result.match.capturedStart(
                               QStringLiteral("tlsAuthBlock")) >= 0) {
                result.kind = SecretBlockKind::TlsAuth;
            } else if (result.match.capturedStart(
                               QStringLiteral("tlsCryptBlock")) >= 0) {
                result.kind = SecretBlockKind::TlsCrypt;
            }
            return result;
        }

        bool redactSecretBlocks(QString &text,
                                StreamState &state,
                                qsizetype initialEndMarkerCharacters)
        {
            if (!patternsAreValid()) {
                return false;
            }
            if (initialEndMarkerCharacters < 0 || initialEndMarkerCharacters > text.size()
                || (initialEndMarkerCharacters > 0 && state.blockKind == SecretBlockKind::None)) {
                return false;
            }

            QString output;
            output.reserve(qMin<qsizetype>(text.size() + 64, MaximumOutputBytes));
            qsizetype cursor = initialEndMarkerCharacters;
            if (initialEndMarkerCharacters > 0) {
                output.append(redactedPrivateKey);
                state.blockKind = SecretBlockKind::None;
            }
            while (cursor < text.size()) {
                if (state.blockKind != SecretBlockKind::None) {
                    const QRegularExpressionMatch endMatch =
                            blockEndExpression(state.blockKind).match(
                                    text, cursor, QRegularExpression::NormalMatch,
                                    trustedUtf16SubjectMatchOption);
                    output.append(redactedPrivateKey);
                    if (!endMatch.hasMatch()) {
                        text = output;
                        return true;
                    }
                    cursor = endMatch.capturedEnd();
                    state.blockKind = SecretBlockKind::None;
                } else {
                    const BlockMatch begin = nextBlockBegin(text, cursor);
                    if (!begin.match.hasMatch()) {
                        output.append(text.sliced(cursor));
                        text = output;
                        return true;
                    }
                    output.append(text.sliced(cursor, begin.match.capturedStart() - cursor));
                    cursor = begin.match.capturedEnd();
                    state.blockKind = begin.kind;
                }

                if (output.size() > MaximumOutputBytes) {
                    return false;
                }
            }

            if (state.blockKind != SecretBlockKind::None) {
                output.append(redactedPrivateKey);
            }
            text = output;
            return true;
        }

        bool applyPattern(QString &text, const QRegularExpression &expression, const QString &replacement)
        {
            if (!expression.isValid()) {
                return false;
            }
            text.replace(expression, replacement);
            return text.size() <= MaximumOutputBytes;
        }

        void clearPendingSecret(StreamState &state)
        {
            state.pendingSecretKind = PendingSecretKind::None;
            state.pendingSecretPhase = PendingSecretPhase::None;
            state.pendingSecretWhitespaceBytes = 0;
        }

        bool appendBounded(QString &output, const QString &value)
        {
            if (value.size() > MaximumOutputBytes - output.size()) {
                return false;
            }
            output.append(value);
            return true;
        }

        bool appendBounded(QString &output, QChar value)
        {
            if (output.size() >= MaximumOutputBytes) {
                return false;
            }
            output.append(value);
            return true;
        }

        bool isOverflowPhase(PendingSecretPhase phase)
        {
            return phase == PendingSecretPhase::OverflowAwaitingSeparator
                    || phase == PendingSecretPhase::OverflowAwaitingValue;
        }

        PendingSecretPhase overflowPhaseFor(PendingSecretPhase phase)
        {
            return phase == PendingSecretPhase::AwaitingSeparator
                    ? PendingSecretPhase::OverflowAwaitingSeparator
                    : PendingSecretPhase::OverflowAwaitingValue;
        }

        bool isSerializedArrayPending(const StreamState &state)
        {
            // This tuple is valid in the persisted v2 stream-state schema. It
            // deliberately remains active until an external cursor/file reset:
            // escaped array closing syntax is ambiguous without the full source.
            return state.pendingSecretKind == PendingSecretKind::Array
                    && state.pendingSecretWhitespaceBytes
                            == MaximumPendingSecretWhitespaceBytes
                    && state.pendingSecretPhase
                            == PendingSecretPhase::AwaitingSeparator;
        }

        StreamState permanentPrivacyMarkerState()
        {
            StreamState state;
            state.pendingSecretKind = PendingSecretKind::Array;
            state.pendingSecretPhase = PendingSecretPhase::AwaitingSeparator;
            state.pendingSecretWhitespaceBytes =
                    MaximumPendingSecretWhitespaceBytes;
            return state;
        }

        bool consumePendingSecret(const QString &text,
                                  StreamState &state,
                                  QString &output,
                                  qsizetype &cursor,
                                  bool &openArrayMarkerAppended)
        {
            bool failClosedMarkerAppended = false;
            while (state.pendingSecretPhase != PendingSecretPhase::None) {
                if (isSerializedArrayPending(state)) {
                    if (!failClosedMarkerAppended) {
                        if (!appendBounded(output, redactedValue)) {
                            return false;
                        }
                        failClosedMarkerAppended = true;
                    }
                    cursor = text.size();
                    return true;
                }
                if (isOverflowPhase(state.pendingSecretPhase)) {
                    if (!failClosedMarkerAppended) {
                        if (!appendBounded(output, redactedValue)) {
                            return false;
                        }
                        failClosedMarkerAppended = true;
                    }
                    while (cursor < text.size() && text.at(cursor).isSpace()) {
                        ++cursor;
                    }
                    if (cursor >= text.size()) {
                        return true;
                    }
                    if (state.pendingSecretPhase
                                == PendingSecretPhase::OverflowAwaitingSeparator) {
                        const QChar separator = text.at(cursor);
                        if (separator == QLatin1Char(':')
                            || separator == QLatin1Char('=')) {
                            ++cursor;
                            state.pendingSecretPhase =
                                    PendingSecretPhase::OverflowAwaitingValue;
                            continue;
                        }
                        state.pendingSecretPhase =
                                PendingSecretPhase::OverflowAwaitingValue;
                        state.pendingSecretWhitespaceBytes = 0;
                        continue;
                    }
                    if (state.pendingSecretKind == PendingSecretKind::Scalar
                        && scalarValueNeedsPermanentPrivacyMarker(text, cursor)) {
                        state = permanentPrivacyMarkerState();
                        cursor = text.size();
                        return true;
                    }
                    if (state.pendingSecretKind == PendingSecretKind::Array
                        && text.at(cursor) == QLatin1Char('[')) {
                        ++cursor;
                        state.secretArrayOpen = true;
                        state.secretArrayDepth = 1;
                        state.secretArrayQuote = {};
                        state.secretArrayEscaped = false;
                        clearPendingSecret(state);
                        openArrayMarkerAppended = true;
                        return true;
                    }
                    state.pendingSecretPhase = PendingSecretPhase::RedactingValue;
                    state.pendingSecretWhitespaceBytes = 0;
                }

                if (state.pendingSecretPhase == PendingSecretPhase::RedactingValue
                    && state.pendingSecretKind == PendingSecretKind::Scalar
                    && scalarValueNeedsPermanentPrivacyMarker(text, cursor)) {
                    if (!failClosedMarkerAppended
                        && !appendBounded(output, redactedValue)) {
                        return false;
                    }
                    state = permanentPrivacyMarkerState();
                    cursor = text.size();
                    return true;
                }

                if (state.pendingSecretPhase == PendingSecretPhase::RedactingValue) {
                    if (!failClosedMarkerAppended) {
                        if (!appendBounded(output, redactedValue)) {
                            return false;
                        }
                        failClosedMarkerAppended = true;
                    }
                    const qsizetype separator = nextRecordSeparatorStart(text, cursor);
                    if (separator < 0) {
                        cursor = text.size();
                        return true;
                    }
                    const qsizetype separatorEnd = recordSeparatorEnd(
                            text, separator);
                    if (!appendBounded(output, text.sliced(
                                                separator,
                                                separatorEnd - separator))) {
                        return false;
                    }
                    cursor = separatorEnd;
                    clearPendingSecret(state);
                    return true;
                }

                while (cursor < text.size() && text.at(cursor).isSpace()) {
                    if (state.pendingSecretWhitespaceBytes
                        >= MaximumPendingSecretWhitespaceBytes) {
                        state.pendingSecretWhitespaceBytes =
                                MaximumPendingSecretWhitespaceBytes;
                        state.pendingSecretPhase = overflowPhaseFor(
                                state.pendingSecretPhase);
                        break;
                    }
                    if (!appendBounded(output, text.at(cursor))) {
                        return false;
                    }
                    ++state.pendingSecretWhitespaceBytes;
                    ++cursor;
                }
                if (isOverflowPhase(state.pendingSecretPhase)) {
                    continue;
                }
                if (cursor >= text.size()) {
                    return true;
                }

                if (state.pendingSecretKind == PendingSecretKind::Scalar
                    && state.pendingSecretPhase == PendingSecretPhase::AwaitingValue
                    && scalarValueNeedsPermanentPrivacyMarker(text, cursor)) {
                    if (!failClosedMarkerAppended
                        && !appendBounded(output, redactedValue)) {
                        return false;
                    }
                    state = permanentPrivacyMarkerState();
                    cursor = text.size();
                    return true;
                }

                const QChar character = text.at(cursor);
                if (state.pendingSecretPhase == PendingSecretPhase::AwaitingSeparator) {
                    if (character == QLatin1Char('\\')) {
                        const qsizetype escapedQuoteStart = cursor;
                        while (cursor < text.size()
                               && text.at(cursor) == QLatin1Char('\\')) {
                            ++cursor;
                        }
                        // A slash run at a source boundary is retained as
                        // serialized-key syntax. The following chunk can then
                        // consume the quote without losing AwaitingSeparator.
                        if (cursor >= text.size()) {
                            if (!appendBounded(output, text.sliced(
                                                       escapedQuoteStart,
                                                       cursor - escapedQuoteStart))) {
                                return false;
                            }
                            if (state.pendingSecretKind == PendingSecretKind::Array) {
                                state.pendingSecretPhase =
                                        PendingSecretPhase::AwaitingSeparator;
                                state.pendingSecretWhitespaceBytes =
                                        MaximumPendingSecretWhitespaceBytes;
                            } else {
                                state.pendingSecretKind = PendingSecretKind::Scalar;
                            }
                            return true;
                        }
                        if (text.at(cursor) == QLatin1Char('"')
                            || text.at(cursor) == QLatin1Char('\'')) {
                            ++cursor;
                            if (!appendBounded(output, text.sliced(
                                                       escapedQuoteStart,
                                                       cursor - escapedQuoteStart))) {
                                return false;
                            }
                            // Keep encoded arrays in the persisted fail-closed
                            // marker state; the raw quote scanner cannot safely
                            // interpret their nested escape depth.
                            if (state.pendingSecretKind == PendingSecretKind::Array) {
                                state.pendingSecretPhase =
                                        PendingSecretPhase::AwaitingSeparator;
                            } else {
                                state.pendingSecretKind = PendingSecretKind::Scalar;
                            }
                            state.pendingSecretWhitespaceBytes =
                                    state.pendingSecretKind == PendingSecretKind::Array
                                    ? MaximumPendingSecretWhitespaceBytes : 0;
                            continue;
                        }
                        cursor = escapedQuoteStart;
                        state.pendingSecretPhase = PendingSecretPhase::RedactingValue;
                        state.pendingSecretWhitespaceBytes = 0;
                        continue;
                    }
                    if (character == QLatin1Char('"')
                        || character == QLatin1Char('\'')) {
                        if (!appendBounded(output, character)) {
                            return false;
                        }
                        ++cursor;
                        state.pendingSecretWhitespaceBytes = 0;
                        continue;
                    }
                    if (character == QLatin1Char(':') || character == QLatin1Char('=')) {
                        if (!appendBounded(output, character)) {
                            return false;
                        }
                        ++cursor;
                        state.pendingSecretPhase = PendingSecretPhase::AwaitingValue;
                        state.pendingSecretWhitespaceBytes = 0;
                        continue;
                    }
                    state.pendingSecretPhase = PendingSecretPhase::RedactingValue;
                    state.pendingSecretWhitespaceBytes = 0;
                    continue;
                }

                if (state.pendingSecretKind == PendingSecretKind::Array
                    && character == QLatin1Char('[')) {
                    ++cursor;
                    state.secretArrayOpen = true;
                    state.secretArrayDepth = 1;
                    state.secretArrayQuote = {};
                    state.secretArrayEscaped = false;
                    clearPendingSecret(state);
                    if (!appendBounded(output, redactedValue)) {
                        return false;
                    }
                    openArrayMarkerAppended = true;
                    return true;
                }

                state.pendingSecretPhase = PendingSecretPhase::RedactingValue;
                state.pendingSecretWhitespaceBytes = 0;
            }
            return true;
        }

        bool redactSecretArrays(QString &text,
                                StreamState &state,
                                qsizetype initialStartCharacters,
                                qsizetype initialPendingCharacters)
        {
            if (!secretArrayStartExpression().isValid()
                || initialStartCharacters < 0 || initialStartCharacters > text.size()
                || initialPendingCharacters < 0 || initialPendingCharacters > text.size()
                || (initialStartCharacters > 0
                    && (state.secretArrayOpen
                        || state.pendingSecretPhase != PendingSecretPhase::None))
                || (initialPendingCharacters > 0
                    && state.pendingSecretPhase == PendingSecretPhase::None)) {
                return false;
            }

            QString output;
            output.reserve(qMin<qsizetype>(text.size() + 64, MaximumOutputBytes));
            qsizetype cursor = 0;
            bool openArrayMarkerAppended = false;
            if (initialPendingCharacters > 0) {
                if (!appendBounded(output, redactedValue)) {
                    return false;
                }
                cursor = initialPendingCharacters;
            }
            if (state.pendingSecretPhase != PendingSecretPhase::None) {
                if (!consumePendingSecret(text, state, output, cursor,
                                          openArrayMarkerAppended)) {
                    return false;
                }
                if (state.pendingSecretPhase != PendingSecretPhase::None
                    && cursor >= text.size()) {
                    text = output;
                    return text.size() <= MaximumOutputBytes;
                }
            }

            if (state.secretArrayOpen && !openArrayMarkerAppended) {
                output.append(redactedValue);
            } else if (initialStartCharacters > 0) {
                output.append(redactedValue);
                cursor = initialStartCharacters;
                state.secretArrayOpen = true;
                state.secretArrayDepth = 1;
                state.secretArrayQuote = {};
                state.secretArrayEscaped = false;
            }

            while (cursor < text.size()) {
                if (!state.secretArrayOpen) {
                    const QRegularExpressionMatch match =
                            secretArrayStartExpression().match(
                                    text, cursor, QRegularExpression::NormalMatch,
                                    trustedUtf16SubjectMatchOption);
                    if (!match.hasMatch()) {
                        output.append(text.sliced(cursor));
                        text = output;
                        return text.size() <= MaximumOutputBytes;
                    }
                    const qsizetype openingBracket = match.capturedEnd() - 1;
                    output.append(text.sliced(cursor, openingBracket - cursor));
                    output.append(redactedValue);
                    cursor = openingBracket + 1;
                    state.secretArrayOpen = true;
                    state.secretArrayDepth = 1;
                    state.secretArrayQuote = {};
                    state.secretArrayEscaped = false;
                }

                bool closed = false;
                for (; cursor < text.size(); ++cursor) {
                    const QChar character = text.at(cursor);
                    if (!state.secretArrayQuote.isNull()) {
                        if (state.secretArrayEscaped) {
                            state.secretArrayEscaped = false;
                        } else if (character == QLatin1Char('\\')) {
                            state.secretArrayEscaped = true;
                        } else if (character == state.secretArrayQuote) {
                            state.secretArrayQuote = {};
                        }
                        continue;
                    }

                    if (character == QLatin1Char('"') || character == QLatin1Char('\'')) {
                        state.secretArrayQuote = character;
                    } else if (character == QLatin1Char('[')) {
                        ++state.secretArrayDepth;
                    } else if (character == QLatin1Char(']')) {
                        if (state.secretArrayDepth <= 1) {
                            state.secretArrayOpen = false;
                            state.secretArrayDepth = 0;
                            state.secretArrayQuote = {};
                            state.secretArrayEscaped = false;
                            ++cursor;
                            closed = true;
                            break;
                        }
                        --state.secretArrayDepth;
                    }
                }
                if (!closed) {
                    text = output;
                    return text.size() <= MaximumOutputBytes;
                }
            }

            text = output;
            return text.size() <= MaximumOutputBytes;
        }

        bool capturePendingSerializedSecret(QString &text, StreamState &state)
        {
            if (state.blockKind != SecretBlockKind::None || state.secretArrayOpen
                || state.pendingSecretPhase != PendingSecretPhase::None) {
                return true;
            }

            for (const PendingSecretKind kind : { PendingSecretKind::Array,
                                                   PendingSecretKind::Scalar }) {
                if (!pendingSerializedSlashRunExpression(kind).match(text).hasMatch()) {
                    continue;
                }
                state.pendingSecretKind = kind;
                state.pendingSecretPhase = PendingSecretPhase::AwaitingSeparator;
                state.pendingSecretWhitespaceBytes =
                        kind == PendingSecretKind::Array
                        ? MaximumPendingSecretWhitespaceBytes : 0;
                return true;
            }

            for (const PendingSecretKind kind : { PendingSecretKind::Array,
                                                   PendingSecretKind::Scalar }) {
                for (const PendingSecretPhase phase : {
                             PendingSecretPhase::AwaitingValue,
                             PendingSecretPhase::AwaitingSeparator }) {
                    const QRegularExpression &expression =
                            phase == PendingSecretPhase::AwaitingValue
                            ? pendingSerializedValueExpression(kind)
                            : pendingSerializedSeparatorExpression(kind);
                    const QRegularExpressionMatch match = expression.match(text);
                    if (!match.hasMatch()) {
                        continue;
                    }

                    const qsizetype whitespaceBytes = match.capturedLength(1);
                    state.pendingSecretKind = kind;
                    if (kind == PendingSecretKind::Array) {
                        state.pendingSecretPhase =
                                PendingSecretPhase::AwaitingSeparator;
                        state.pendingSecretWhitespaceBytes =
                                MaximumPendingSecretWhitespaceBytes;
                    } else {
                        state.pendingSecretWhitespaceBytes = qMin(
                                whitespaceBytes, MaximumPendingSecretWhitespaceBytes);
                        if (whitespaceBytes > MaximumPendingSecretWhitespaceBytes) {
                            state.pendingSecretPhase = overflowPhaseFor(phase);
                            text.replace(match.capturedStart(1), whitespaceBytes,
                                         redactedValue);
                        } else {
                            state.pendingSecretPhase = phase;
                        }
                    }
                    return text.size() <= MaximumOutputBytes;
                }
            }

            return true;
        }

        bool capturePendingSecret(QString &text, StreamState &state)
        {
            if (state.blockKind != SecretBlockKind::None || state.secretArrayOpen
                || state.pendingSecretPhase != PendingSecretPhase::None) {
                return true;
            }
            if (!capturePendingSerializedSecret(text, state)
                || state.pendingSecretPhase != PendingSecretPhase::None) {
                return text.size() <= MaximumOutputBytes;
            }

            for (const PendingSecretKind kind : { PendingSecretKind::Array,
                                                  PendingSecretKind::Scalar }) {
                for (const PendingSecretPhase phase : {
                             PendingSecretPhase::AwaitingValue,
                             PendingSecretPhase::AwaitingSeparator }) {
                    const QRegularExpression &expression =
                            phase == PendingSecretPhase::AwaitingValue
                            ? pendingValueExpression(kind)
                            : pendingSeparatorExpression(kind);
                    const QRegularExpressionMatch match = expression.match(text);
                    if (!match.hasMatch()) {
                        continue;
                    }

                    const qsizetype whitespaceBytes = match.capturedLength(1);
                    state.pendingSecretKind = kind;
                    state.pendingSecretWhitespaceBytes = qMin(
                            whitespaceBytes, MaximumPendingSecretWhitespaceBytes);
                    if (whitespaceBytes > MaximumPendingSecretWhitespaceBytes) {
                        state.pendingSecretPhase = overflowPhaseFor(phase);
                        text.replace(match.capturedStart(1), whitespaceBytes, redactedValue);
                    } else {
                        state.pendingSecretPhase = phase;
                    }
                    return text.size() <= MaximumOutputBytes;
                }
            }
            return true;
        }

        bool redactSerializedSecretRecords(QString &text, StreamState &state)
        {
            if (state.pendingSecretPhase != PendingSecretPhase::None) {
                return true;
            }

            // The raw-array pass can leave an unclosed array state after it has
            // already replaced the array tail. Its preserved prefix may still
            // contain an earlier serialized scalar and must be scanned.

            QString output;
            output.reserve(qMin<qsizetype>(text.size() + 64, MaximumOutputBytes));
            qsizetype cursor = 0;
            while (cursor < text.size()) {
                const QRegularExpressionMatch match =
                        allSerializedKeysWithSeparatorExpression().match(
                                text, cursor, QRegularExpression::NormalMatch,
                                trustedUtf16SubjectMatchOption);
                if (!match.hasMatch()) {
                    return appendBounded(output, text.sliced(cursor))
                            && (text = output).size() <= MaximumOutputBytes;
                }
                const PendingSecretKind kind = match.capturedStart(
                                                       QStringLiteral(
                                                               "serializedArray"))
                                >= 0
                        ? PendingSecretKind::Array : PendingSecretKind::Scalar;

                if (!appendBounded(output, text.sliced(
                                           cursor,
                                           match.capturedStart() - cursor))
                    || !appendBounded(output, redactedValue)) {
                    return false;
                }

                qsizetype valueCursor = match.capturedEnd();
                qsizetype whitespaceBytes = 0;
                while (valueCursor < text.size() && text.at(valueCursor).isSpace()) {
                    ++valueCursor;
                    ++whitespaceBytes;
                }
                if (valueCursor >= text.size()) {
                    if (kind == PendingSecretKind::Array) {
                        state = permanentPrivacyMarkerState();
                    } else {
                        state.pendingSecretKind = kind;
                        state.pendingSecretPhase = PendingSecretPhase::AwaitingValue;
                        state.pendingSecretWhitespaceBytes = qMin(
                                whitespaceBytes, MaximumPendingSecretWhitespaceBytes);
                    }
                    text = output;
                    return text.size() <= MaximumOutputBytes;
                }

                if (kind == PendingSecretKind::Array
                    && text.at(valueCursor) == QLatin1Char('[')) {
                    state = permanentPrivacyMarkerState();
                    text = output;
                    return text.size() <= MaximumOutputBytes;
                }

                const qsizetype separator = nextRecordSeparatorStart(
                        text, valueCursor);
                if (separator < 0) {
                    cursor = text.size();
                    continue;
                }
                const qsizetype separatorEnd = recordSeparatorEnd(
                        text, separator);
                if (!appendBounded(output, text.sliced(
                                            separator,
                                            separatorEnd - separator))) {
                    return false;
                }
                cursor = separatorEnd;
            }

            text = output;
            return text.size() <= MaximumOutputBytes;
        }

        bool redactCredentialPatterns(QString &text)
        {
            // Header values are credentials regardless of their authentication
            // scheme. Redacting the whole value avoids partial Bearer/Basic
            // parsing and keeps the non-sensitive header name for diagnostics.
            static const QRegularExpression authorizationHeader(
                    QStringLiteral(R"re((?im)^([ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*)[^\r\n]+)re"));
            static const QRegularExpression cookieHeader(
                    QStringLiteral(R"re((?im)^([ \t]*(?:set-cookie|cookie)[ \t]*:[ \t]*)[^\r\n]+)re"));
            static const QRegularExpression bearerValue(
                    QStringLiteral(R"re((?i)(\bbearer[ \t]+)[A-Z0-9._~+/=-]{4,})re"));
            static const QRegularExpression urlUserInfo(
                    QStringLiteral(R"re((?i)(\b[A-Z][A-Z0-9+.-]{1,31}://)[^/\s@]+@)re"));
            static const QRegularExpression urlQuerySecret(
                    QStringLiteral(
                            R"re((?i)([?&](?:access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?token|log[_-]?token|client[_-]?secret|api[_-]?key|password|passwd|pwd|passphrase|secret|token|installation[_-]?(?:uuid|id))=)[^&#\s]*)re"));

            // The key list intentionally excludes broad identifiers such as
            // host, domain, address, IP, UUID, and public_key. Those values are
            // essential for route and health diagnostics and are not secrets by
            // themselves. Installation identifiers are included only when a
            // field name identifies them as such.
            static const QRegularExpression doubleQuotedValue(
                    QStringLiteral(R"re(((?<![A-Z0-9_-])["']?)re") + secretKeyPattern()
                            + QStringLiteral(R"re(["']?\s*[:=]\s*")((?:\\.|[^"\\\r\n])*)("))re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression singleQuotedValue(
                    QStringLiteral(R"re(((?<![A-Z0-9_-])["']?)re") + secretKeyPattern()
                            + QStringLiteral(R"re(["']?\s*[:=]\s*')((?:\\.|[^'\\\r\n])*)('))re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression unquotedValue(
                    QStringLiteral(R"re(((?<![A-Z0-9_-])["']?)re") + secretKeyPattern()
                            + QStringLiteral(R"re(["']?\s*[:=]\s*)(?!["'])([^\r\n]+))re"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression commandLineValue(
                    QStringLiteral(R"re(((?<![A-Z0-9_-])--)re") + secretKeyPattern()
                            + QStringLiteral(
                                    R"re((?:[ \t]*=[ \t]*|[ \t]+))(?:(?:"(?:\\.|[^"\\])*")|(?:'(?:\\.|[^'\\])*')|[^\s]+))re"),
                    QRegularExpression::CaseInsensitiveOption);

            return applyPattern(text, authorizationHeader, QStringLiteral("\\1***"))
                    && applyPattern(text, cookieHeader, QStringLiteral("\\1***"))
                    && applyPattern(text, bearerValue, QStringLiteral("\\1***"))
                    && applyPattern(text, urlUserInfo, QStringLiteral("\\1***@"))
                    && applyPattern(text, urlQuerySecret, QStringLiteral("\\1***"))
                    && applyPattern(text, doubleQuotedValue, QStringLiteral("\\1***\\3"))
                    && applyPattern(text, singleQuotedValue, QStringLiteral("\\1***\\3"))
                    && applyPattern(text, unquotedValue, QStringLiteral("\\1***"))
                    && applyPattern(text, commandLineValue, QStringLiteral("\\1***"));
        }

        void redactPartialRecords(QString &text, bool startsInsideRecord, bool endsInsideRecord)
        {
            if (startsInsideRecord) {
                const qsizetype separator = nextRecordSeparatorStart(text);
                if (separator < 0) {
                    text = redactedPartialRecord;
                    return;
                }
                text.replace(0, separator, redactedPartialRecord);
            }

            if (endsInsideRecord) {
                const qsizetype suffixStart = lastRecordSeparatorEnd(text);
                text.replace(suffixStart, text.size() - suffixStart, redactedPartialRecord);
            }
        }
    }

    bool advancePrivateKeyBlockState(const QByteArray &lookbehind,
                                     const QByteArray &input,
                                     bool initiallyOpen)
    {
        StreamState state;
        state.blockKind = initiallyOpen ? SecretBlockKind::PrivateKey : SecretBlockKind::None;
        return advanceStreamState(lookbehind, input, state).blockKind == SecretBlockKind::PrivateKey;
    }

    bool privateKeyBlockOpenAtEnd(const QByteArray &input, bool initiallyOpen)
    {
        bool open = initiallyOpen;
        QByteArray lookbehind;
        qsizetype offset = 0;
        while (offset < input.size()) {
            const qsizetype bytes = qMin<qsizetype>(
                    MaximumPrivateKeyLookbehindBytes, input.size() - offset);
            const QByteArray block = input.mid(offset, bytes);
            open = advancePrivateKeyBlockState(lookbehind, block, open);
            if (block.size() >= MaximumPrivateKeyMarkerBytes) {
                lookbehind = block.right(MaximumPrivateKeyMarkerBytes);
            } else {
                lookbehind = (lookbehind + block).right(MaximumPrivateKeyMarkerBytes);
            }
            offset += bytes;
        }
        return open;
    }

    StreamBoundary inspectStreamBoundary(const QByteArray &lookbehind,
                                         const QByteArray &input,
                                         const StreamState &initialState)
    {
        if (!patternsAreValid() || lookbehind.isEmpty() || input.isEmpty()) {
            return {};
        }

        const QString tail = QString::fromUtf8(
                lookbehind.right(MaximumPrivateKeyMarkerBytes));
        const QString prefix = QString::fromUtf8(
                input.first(MaximumPrivateKeyMarkerBytes));
        const QString combined = tail + prefix;
        const qsizetype boundary = tail.size();

        auto crossingMatch = [&](const QRegularExpression &expression) {
            QRegularExpressionMatch result;
            QRegularExpressionMatchIterator matches = expression.globalMatch(combined);
            while (matches.hasNext()) {
                const QRegularExpressionMatch match = matches.next();
                if (match.capturedStart() < boundary && match.capturedEnd() > boundary) {
                    result = match;
                    break;
                }
            }
            return result;
        };

        StreamBoundary result;
        if (initialState.blockKind != SecretBlockKind::None) {
            const QRegularExpressionMatch end =
                    crossingMatch(blockEndExpression(initialState.blockKind));
            if (end.hasMatch()) {
                result.endBlockMarkerCharactersInInput = end.capturedEnd() - boundary;
            }
        } else {
            qsizetype earliestStart = combined.size() + 1;
            for (const SecretBlockKind kind : { SecretBlockKind::PrivateKey,
                                                SecretBlockKind::OpenVpnStaticKey,
                                                SecretBlockKind::TlsAuth,
                                                SecretBlockKind::TlsCrypt }) {
                const QRegularExpressionMatch begin = crossingMatch(blockBeginExpression(kind));
                if (begin.hasMatch() && begin.capturedStart() < earliestStart) {
                    earliestStart = begin.capturedStart();
                    result.beginBlockKind = kind;
                }
            }
        }

        if (result.beginBlockKind == SecretBlockKind::None
            && result.endBlockMarkerCharactersInInput == 0
            && !initialState.secretArrayOpen
            && !isSerializedArrayPending(initialState)
            && (initialState.pendingSecretPhase == PendingSecretPhase::None
                || initialState.pendingSecretPhase
                        == PendingSecretPhase::AwaitingSeparator
                || initialState.pendingSecretPhase
                        == PendingSecretPhase::RedactingValue)) {
            const QRegularExpressionMatch arrayStart =
                    crossingMatch(secretArrayStartExpression());
            if (arrayStart.hasMatch()) {
                result.secretArrayStartCharactersInInput =
                        arrayStart.capturedEnd() - boundary;
            } else {
                QRegularExpressionMatch keyMatch;
                PendingSecretKind keyKind = PendingSecretKind::None;
                bool serializedKey = false;
                for (const PendingSecretKind kind : { PendingSecretKind::Array,
                                                       PendingSecretKind::Scalar }) {
                    const QRegularExpressionMatch candidate = crossingMatch(
                            pendingSerializedSlashRunExpression(kind));
                    if (candidate.hasMatch()
                        && (!keyMatch.hasMatch()
                            || candidate.capturedStart() < keyMatch.capturedStart())) {
                        keyMatch = candidate;
                        keyKind = kind;
                        serializedKey = true;
                    }
                }
                for (const PendingSecretKind kind : { PendingSecretKind::Array,
                                                       PendingSecretKind::Scalar }) {
                    const QRegularExpressionMatch candidate = crossingMatch(
                            serializedBoundarySecretKeyExpression(kind));
                    if (candidate.hasMatch()
                        && (!keyMatch.hasMatch()
                            || candidate.capturedStart() < keyMatch.capturedStart())) {
                        keyMatch = candidate;
                        keyKind = kind;
                        serializedKey = true;
                    }
                }
                for (const PendingSecretKind kind : { PendingSecretKind::Array,
                                                       PendingSecretKind::Scalar }) {
                    const QRegularExpressionMatch candidate = crossingMatch(
                            boundarySecretKeyExpression(kind));
                    if (candidate.hasMatch()
                        && (!keyMatch.hasMatch()
                            || candidate.capturedStart() < keyMatch.capturedStart())) {
                        keyMatch = candidate;
                        keyKind = kind;
                        serializedKey = false;
                    }
                }

                if (keyMatch.hasMatch()) {
                    qsizetype syntaxCursor = keyMatch.capturedEnd();
                    qsizetype whitespaceBytes = 0;
                    while (syntaxCursor < combined.size()
                           && combined.at(syntaxCursor).isSpace()) {
                        ++syntaxCursor;
                        ++whitespaceBytes;
                    }

                    PendingSecretPhase phase = PendingSecretPhase::AwaitingSeparator;
                    if (syntaxCursor < combined.size()) {
                        const QChar separator = combined.at(syntaxCursor);
                        if (separator == QLatin1Char(':')
                            || separator == QLatin1Char('=')) {
                            ++syntaxCursor;
                            whitespaceBytes = 0;
                            while (syntaxCursor < combined.size()
                                   && combined.at(syntaxCursor).isSpace()) {
                                ++syntaxCursor;
                                ++whitespaceBytes;
                            }
                            phase = syntaxCursor == combined.size()
                                    ? PendingSecretPhase::AwaitingValue
                                    : PendingSecretPhase::RedactingValue;
                        } else {
                            phase = PendingSecretPhase::RedactingValue;
                            whitespaceBytes = 0;
                        }
                    }

                    result.pendingSecretKind = keyKind;
                    if (serializedKey && keyKind == PendingSecretKind::Array) {
                        result.pendingSecretPhase =
                                PendingSecretPhase::AwaitingSeparator;
                        whitespaceBytes = MaximumPendingSecretWhitespaceBytes;
                    } else {
                        result.pendingSecretPhase = phase;
                    }
                    result.pendingSecretCharactersInInput = qBound<qsizetype>(
                            1, syntaxCursor - boundary, prefix.size());
                    result.pendingSecretWhitespaceBytes = qMin(
                            whitespaceBytes, MaximumPendingSecretWhitespaceBytes);
                }
            }
        }
        return result;
    }

    StreamState advanceStreamState(const QByteArray &lookbehind,
                                   const QByteArray &input,
                                   const StreamState &initialState)
    {
        const StreamBoundary boundary = inspectStreamBoundary(
                lookbehind, input, initialState);
        ChunkContext context;
        context.endsInsideRecord = !input.isEmpty()
                && !input.endsWith('\n') && !input.endsWith('\r');
        context.streamState = initialState;
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
        return sanitize(input, context).streamState;
    }

    PrivateKeyBoundary inspectPrivateKeyBoundary(const QByteArray &lookbehind,
                                                 const QByteArray &input)
    {
        PrivateKeyBoundary result;
        result.beginMarkerCrossesBoundary =
                inspectStreamBoundary(lookbehind, input).beginBlockKind
                == SecretBlockKind::PrivateKey;
        StreamState openState;
        openState.blockKind = SecretBlockKind::PrivateKey;
        result.endMarkerCharactersInInput = inspectStreamBoundary(
                lookbehind, input, openState).endBlockMarkerCharactersInInput;
        return result;
    }

    SanitizedChunk sanitize(const QByteArray &input,
                            const ChunkContext &context,
                            const QStringList &sensitiveValues)
    {
        auto failClosedState = context.streamState;
        failClosedState.blockKind = SecretBlockKind::PrivateKey;
        if (input.size() > MaximumInputBytes) {
            return { redactedChunk, true, failClosedState };
        }

        QString text = QString::fromUtf8(input);
        StreamState state = context.streamState;
        const bool boundaryPendingSpecified = context.boundaryPendingSecretKind
                        != PendingSecretKind::None
                && context.boundaryPendingSecretPhase != PendingSecretPhase::None
                && context.boundaryPendingSecretCharacters > 0;
        const bool partialScalarConsumesCrossingAssignment =
                state.pendingSecretKind == PendingSecretKind::Scalar
                && state.pendingSecretPhase == PendingSecretPhase::RedactingValue
                && (boundaryPendingSpecified
                    || context.secretArrayStartCharacters > 0);
        if (partialScalarConsumesCrossingAssignment) {
            return { redactedChunk, false, permanentPrivacyMarkerState() };
        }
        if ((context.boundaryPendingSecretKind == PendingSecretKind::None)
                    != (context.boundaryPendingSecretPhase == PendingSecretPhase::None)
            || (context.boundaryPendingSecretKind != PendingSecretKind::None)
                    != (context.boundaryPendingSecretCharacters > 0)
            || context.boundaryPendingSecretWhitespaceBytes < 0
            || context.boundaryPendingSecretWhitespaceBytes
                    > MaximumPendingSecretWhitespaceBytes
            || (!boundaryPendingSpecified
                && context.boundaryPendingSecretWhitespaceBytes != 0)
            || (boundaryPendingSpecified
                && state.pendingSecretPhase != PendingSecretPhase::None
                && state.pendingSecretPhase
                        != PendingSecretPhase::AwaitingSeparator)) {
            return { redactedChunk, true, failClosedState };
        }
        const bool preserveSerializedArrayMarker = isSerializedArrayPending(state);
        if (boundaryPendingSpecified && !preserveSerializedArrayMarker) {
            state.pendingSecretKind = context.boundaryPendingSecretKind;
            state.pendingSecretPhase = context.boundaryPendingSecretPhase;
            state.pendingSecretWhitespaceBytes =
                    context.boundaryPendingSecretWhitespaceBytes;
        }
        if (context.privateKeyBlockOpen && state.blockKind == SecretBlockKind::None) {
            state.blockKind = SecretBlockKind::PrivateKey;
        }
        if (state.blockKind == SecretBlockKind::None
            && context.boundaryBlockKind != SecretBlockKind::None) {
            state.blockKind = context.boundaryBlockKind;
        }
        if (context.secretArrayStartCharacters > 0
            && state.pendingSecretPhase != PendingSecretPhase::None) {
            // A key reconstructed from the prefix and a crossing raw-array
            // start can describe the same assignment or two overlapping ones.
            // Do not feed both cursors to the stateful parser; persist the
            // schema-valid privacy marker instead.
            return { redactedChunk, false, permanentPrivacyMarkerState() };
        }
        bool trailingPartialScalarValue = false;
        if (hasAmbiguousSensitiveAssignments(
                    text,
                    state.pendingSecretPhase != PendingSecretPhase::None,
                    context.boundaryPendingSecretCharacters,
                    context.endsInsideRecord,
                    trailingPartialScalarValue)) {
            const StreamState privacyState = permanentPrivacyMarkerState();
            return { redactedChunk, false, privacyState };
        }
        QString trailingPendingProbe = text;
        StreamState trailingPendingState;
        if (!capturePendingSecret(trailingPendingProbe, trailingPendingState)) {
            return { redactedChunk, true, failClosedState };
        }
        const bool trailingPendingCaptured =
                trailingPendingState.pendingSecretPhase
                != PendingSecretPhase::None;
        const qsizetype endMarkerCharacters =
                context.secretBlockEndMarkerCharacters > 0
                ? context.secretBlockEndMarkerCharacters
                : context.privateKeyEndMarkerCharacters;
        if (!redactSecretBlocks(text, state, endMarkerCharacters)) {
            return { redactedChunk, true, failClosedState };
        }
        const qsizetype boundaryPendingCharacters = preserveSerializedArrayMarker
                ? 0 : context.boundaryPendingSecretCharacters;
        if (!redactSecretArrays(text, state, context.secretArrayStartCharacters,
                                boundaryPendingCharacters)) {
            return { redactedChunk, true, failClosedState };
        }
        if (!redactSerializedSecretRecords(text, state)) {
            return { redactedChunk, true, failClosedState };
        }
        if (!capturePendingSecret(text, state)) {
            return { redactedChunk, true, failClosedState };
        }
        // An earlier block, array, or record match can remove a later pending
        // key on the same record. Restore the state captured from the original
        // upload copy so the next source chunk remains fail-closed.
        if (trailingPendingCaptured
            && state.blockKind == SecretBlockKind::None
            && !state.secretArrayOpen
            && (!isSerializedArrayPending(state)
                || isSerializedArrayPending(trailingPendingState))) {
            state.pendingSecretKind = trailingPendingState.pendingSecretKind;
            state.pendingSecretPhase = trailingPendingState.pendingSecretPhase;
            state.pendingSecretWhitespaceBytes =
                    trailingPendingState.pendingSecretWhitespaceBytes;
        }

        if (!redactCredentialPatterns(text)) {
            return { redactedChunk,
                     state.blockKind == SecretBlockKind::PrivateKey,
                     state };
        }

        redactPartialRecords(text, context.startsInsideRecord, context.endsInsideRecord);

        for (const QString &sensitiveValue : sensitiveValues) {
            if (sensitiveValue.size() >= 8) {
                text.replace(sensitiveValue, redactedValue, Qt::CaseSensitive);
            }
        }

        // Preserve an incomplete scalar value record across a source chunk.
        // This lets the continuation detect an odd terminal backslash before
        // the physical newline instead of clearing the key and exposing the
        // continued value record. Stronger block/array/pending states dominate.
        if (trailingPartialScalarValue
            && state.blockKind == SecretBlockKind::None
            && !state.secretArrayOpen
            && state.pendingSecretPhase == PendingSecretPhase::None) {
            state.pendingSecretKind = PendingSecretKind::Scalar;
            state.pendingSecretPhase = PendingSecretPhase::RedactingValue;
            state.pendingSecretWhitespaceBytes = 0;
        }

        const QByteArray output = text.toUtf8();
        if (output.size() > MaximumOutputBytes) {
            return { redactedChunk,
                     state.blockKind == SecretBlockKind::PrivateKey,
                     state };
        }
        return { output,
                 state.blockKind == SecretBlockKind::PrivateKey,
                 state };
    }
}
