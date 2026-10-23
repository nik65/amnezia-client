#pragma once

#include <QByteArray>

namespace amnezia::configPayloadCodec
{
// These bounds apply to configuration data, independently of the four-byte
// qCompress size hint. The compressed allowance includes zlib wrapper overhead
// for an incompressible payload at the decoded limit.
constexpr qsizetype maximumDecodedBytes = 16 * 1024 * 1024;
constexpr qsizetype maximumCompressedBytes = maximumDecodedBytes + maximumDecodedBytes / 1000 + 64;
constexpr qsizetype maximumEncodedTextBytes = ((maximumCompressedBytes + 2) / 3) * 4 + 6;

enum class Status { NotCompressed, Decoded, Invalid, TooLarge };

struct Result
{
    Status status = Status::Invalid;
    QByteArray data;

    bool accepted() const { return status == Status::NotCompressed || status == Status::Decoded; }
};

// Envelope recognition only; decode must still verify the stream and limits.
bool hasCompressedEnvelope(const QByteArray &input);

// Recognized qCompress streams are inflated incrementally and require a complete
// checksum-verified stream with no trailing bytes. Errors never return partial
// output. Non-compressed data is returned unchanged within the same output cap.
Result decode(const QByteArray &input, qsizetype maximum = maximumDecodedBytes);
}
