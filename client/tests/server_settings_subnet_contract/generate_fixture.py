"""Extract actual pure model functions; do not compile the application."""
import pathlib
import sys

root, output = map(pathlib.Path, sys.argv[1:3])
names = ('WireGuard', 'Awg', 'OpenVpn')
files = ('wireGuard', 'awg', 'openVpn')
parts = ['#include <QJsonObject>\n#include <QJsonDocument>\n'
         '#include "core/utils/constants/configKeys.h"\n']
for stem in files:
    parts.append(f'#include "core/models/protocols/{stem}ProtocolConfig.h"\n')
parts.append('namespace amnezia {\n')
for name, stem in zip(names, files):
    text = (root / f'core/models/protocols/{stem}ProtocolConfig.cpp').read_text()
    for signature in (f'QJsonObject {name}ServerConfig::toJson() const',
                      f'{name}ServerConfig {name}ServerConfig::fromJson(',
                      f'bool {name}ServerConfig::hasEqualServerSettings('):
        start = text.index(signature)
        brace = text.index('{', start)
        depth, end = 1, brace + 1
        while depth:
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        parts.append(text[start:end] + '\n')
parts.append('}\n')
output.write_text(''.join(parts))
