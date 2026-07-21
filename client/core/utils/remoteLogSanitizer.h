#ifndef REMOTELOGSANITIZER_H
#define REMOTELOGSANITIZER_H

#include <QByteArray>
#include <QChar>
#include <QStringList>
#include <QtGlobal>

namespace amnezia::remoteLogSanitizer
{
    inline constexpr qsizetype MaximumInputBytes = 15 * 1024 * 1024;
    inline constexpr qsizetype MaximumOutputBytes = 32 * 1024 * 1024;
    inline constexpr qsizetype MaximumPrivateKeyLookbehindBytes = 1024 * 1024;
    inline constexpr qsizetype MaximumPrivateKeyMarkerBytes = 256;
    inline constexpr qsizetype MaximumPendingSecretWhitespaceBytes = 64 * 1024;

    enum class SecretBlockKind : quint8
    {
        None = 0,
        PrivateKey,
        OpenVpnStaticKey,
        TlsAuth,
        TlsCrypt
    };

    enum class PendingSecretKind : quint8
    {
        None = 0,
        Scalar,
        Array
    };

    enum class PendingSecretPhase : quint8
    {
        None = 0,
        AwaitingSeparator,
        AwaitingValue,
        OverflowAwaitingSeparator,
        OverflowAwaitingValue,
        RedactingValue
    };

    struct StreamState
    {
        SecretBlockKind blockKind = SecretBlockKind::None;
        bool secretArrayOpen = false;
        qsizetype secretArrayDepth = 0;
        QChar secretArrayQuote;
        bool secretArrayEscaped = false;
        PendingSecretKind pendingSecretKind = PendingSecretKind::None;
        PendingSecretPhase pendingSecretPhase = PendingSecretPhase::None;
        qsizetype pendingSecretWhitespaceBytes = 0;
    };

    struct ChunkContext
    {
        bool startsInsideRecord = false;
        bool endsInsideRecord = false;
        bool privateKeyBlockOpen = false;
        qsizetype privateKeyEndMarkerCharacters = 0;
        StreamState streamState;
        SecretBlockKind boundaryBlockKind = SecretBlockKind::None;
        qsizetype secretBlockEndMarkerCharacters = 0;
        qsizetype secretArrayStartCharacters = 0;
        PendingSecretKind boundaryPendingSecretKind = PendingSecretKind::None;
        PendingSecretPhase boundaryPendingSecretPhase = PendingSecretPhase::None;
        qsizetype boundaryPendingSecretCharacters = 0;
        qsizetype boundaryPendingSecretWhitespaceBytes = 0;
    };

    struct PrivateKeyBoundary
    {
        bool beginMarkerCrossesBoundary = false;
        qsizetype endMarkerCharactersInInput = 0;
    };

    struct StreamBoundary
    {
        SecretBlockKind beginBlockKind = SecretBlockKind::None;
        qsizetype endBlockMarkerCharactersInInput = 0;
        qsizetype secretArrayStartCharactersInInput = 0;
        PendingSecretKind pendingSecretKind = PendingSecretKind::None;
        PendingSecretPhase pendingSecretPhase = PendingSecretPhase::None;
        qsizetype pendingSecretCharactersInInput = 0;
        qsizetype pendingSecretWhitespaceBytes = 0;
    };

    struct SanitizedChunk
    {
        QByteArray data;
        bool privateKeyBlockOpen = false;
        StreamState streamState;
    };

    // Sanitizes an upload copy only. Source bytes, offsets, and local log files
    // remain untouched so callers can keep cursor and rotation semantics based
    // on the original log stream.
    SanitizedChunk sanitize(const QByteArray &input,
                            const ChunkContext &context = {},
                            const QStringList &sensitiveValues = {});

    // Used when a persisted cursor is no longer applicable and collection
    // resumes from a bounded tail window rather than from the start of a file.
    bool privateKeyBlockOpenAtEnd(const QByteArray &input, bool initiallyOpen = false);

    // Advances an already-known stream state over one bounded input block.
    // lookbehind is used only to reconstruct an ASCII marker split at the
    // block boundary and may be empty for the first block.
    bool advancePrivateKeyBlockState(const QByteArray &lookbehind,
                                     const QByteArray &input,
                                     bool initiallyOpen);

    // Advances all stateful redaction constructs over a bounded raw block.
    // Callers can persist the returned state alongside the raw source cursor.
    StreamState advanceStreamState(const QByteArray &lookbehind,
                                   const QByteArray &input,
                                   const StreamState &initialState = {});

    // Recognizes a PEM marker split exactly between two source chunks. This is
    // separate from line-fragment redaction because the private-key body spans
    // multiple records after the marker line.
    PrivateKeyBoundary inspectPrivateKeyBoundary(const QByteArray &lookbehind,
                                                 const QByteArray &input);

    StreamBoundary inspectStreamBoundary(const QByteArray &lookbehind,
                                         const QByteArray &input,
                                         const StreamState &initialState = {});
}

#endif // REMOTELOGSANITIZER_H
