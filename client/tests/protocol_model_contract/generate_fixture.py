"""Extract actual pure protocol model methods against their real headers."""
from pathlib import Path
import sys
root, output = map(Path, sys.argv[1:3])
parts = ['#include "core/models/protocols/awgProtocolConfig.h"\n'
         '#include "core/models/protocols/wireGuardProtocolConfig.h"\n'
         '#include "core/utils/constants/configKeys.h"\n#include <QJsonArray>\n'
         'namespace amnezia {\n']
for stem, name in [('awg', 'Awg'), ('wireGuard', 'WireGuard')]:
    text = (root / f'core/models/protocols/{stem}ProtocolConfig.cpp').read_text(encoding='utf-8')
    signatures = [f'QJsonObject {name}ClientConfig::toJson() const',
                  f'{name}ClientConfig {name}ClientConfig::fromJson(']
    if name == 'Awg':
        signatures.append('bool AwgProtocolConfig::isPacketSizeEqual(')
    for signature in signatures:
        start = text.index(signature)
        brace = text.index('{', start)
        end, depth = brace + 1, 1
        while depth:
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        parts.append(text[start:end] + '\n')
parts.append('}\n')
output.write_text(''.join(parts), encoding='utf-8')
