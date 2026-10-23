#include "configPayloadCodec.h"

#include <algorithm>
#include <array>
#include <utility>
#include <zlib.h>

namespace amnezia::configPayloadCodec
{
namespace
{
bool hasPlainConfigurationPrefix(const QByteArray &input)
{
    qsizetype position = input.startsWith("\xef\xbb\xbf") ? 3 : 0;
    while (position < input.size()) {
        const char byte = input.at(position);
        if (byte != ' ' && byte != '\t' && byte != '\r' && byte != '\n' && byte != '\f' && byte != '\v')
            return byte == '{' || byte == '[' || byte == '#' || byte == ';';
        ++position;
    }
    return false;
}

bool hasPlainTextPrefix(const QByteArray &input)
{
    const qsizetype position = input.startsWith("\xef\xbb\xbf") ? 3 : 0;
    const auto count = std::min<qsizetype>(4, input.size() - position);
    for (qsizetype i = 0; i < count; ++i) {
        const auto byte = static_cast<unsigned char>(input.at(position + i));
        if ((byte < 32 || byte > 126) && byte != '\t' && byte != '\n' && byte != '\r'
            && byte != '\f' && byte != '\v')
            return false;
    }
    return true;
}

bool hasZlibHeader(const QByteArray &input)
{
    if (input.size() < 6)
        return false;
    const auto cmf = static_cast<unsigned char>(input.at(4));
    const auto flg = static_cast<unsigned char>(input.at(5));
    return (cmf & 0x0f) == Z_DEFLATED && (cmf >> 4) <= 7 && ((unsigned(cmf) << 8) + flg) % 31 == 0;
}

struct Inflater
{
    z_stream stream{};
    bool initialized = false;
    ~Inflater()
    {
        if (initialized)
            inflateEnd(&stream);
    }
};
}

bool hasCompressedEnvelope(const QByteArray &input)
{
    return (input.size() == 4 && input == QByteArray(4, '\0'))
            || (!hasPlainConfigurationPrefix(input) && !hasPlainTextPrefix(input) && hasZlibHeader(input));
}

Result decode(const QByteArray &input, qsizetype maximum)
{
    if (maximum < 0 || maximum > maximumDecodedBytes)
        return { Status::Invalid, {} };
    const auto compressedLimit = maximum + maximum / 1000 + 64;
    if (input.size() > compressedLimit)
        return { Status::TooLarge, {} };

    // Qt also represents an empty compressed array as a zero size header alone.
    if (input.size() == 4 && input == QByteArray(4, '\0'))
        return { Status::Decoded, {} };
    // Raw JSON/config text may coincidentally contain a valid two-byte zlib
    // header at offsets4/5. A normal bounded qCompress length prefix contains
    // non-text zero/one bytes. Preserve text imports before sniffing the stream.
    if (!hasCompressedEnvelope(input)) {
        if (input.size() > maximum)
            return { Status::TooLarge, {} };
        return { Status::NotCompressed, input };
    }

    Inflater inflater;
    if (inflateInit(&inflater.stream) != Z_OK)
        return { Status::Invalid, {} };
    inflater.initialized = true;
    // The bounded input fits uInt on every supported platform. In particular,
    // the attacker-controlled qCompress size prefix is never an allocation size.
    inflater.stream.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(input.constData() + 4));
    inflater.stream.avail_in = static_cast<uInt>(input.size() - 4);
    QByteArray output;
    std::array<char, 64 * 1024> chunk{};
    for (;;) {
        const auto remaining = maximum - output.size();
        const auto available = static_cast<uInt>(std::min<qsizetype>(chunk.size(), remaining + 1));
        inflater.stream.next_out = reinterpret_cast<Bytef *>(chunk.data());
        inflater.stream.avail_out = available;
        const auto inputBefore = inflater.stream.avail_in;
        const int status = inflate(&inflater.stream, Z_NO_FLUSH);
        const auto produced = available - inflater.stream.avail_out;
        if (static_cast<qsizetype>(produced) > remaining)
            return { Status::TooLarge, {} };
        if (produced)
            output.append(chunk.data(), produced);
        if (status == Z_STREAM_END) {
            if (inflater.stream.avail_in != 0)
                return { Status::Invalid, {} };
            return { Status::Decoded, std::move(output) };
        }
        if (status != Z_OK || (produced == 0 && inputBefore == inflater.stream.avail_in))
            return { Status::Invalid, {} };
    }
}
}
