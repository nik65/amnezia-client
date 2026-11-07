"""Compile actual profile JSON methods with inert container-only dependencies."""
from pathlib import Path
import sys

root, output = map(Path, sys.argv[1:3])

def function(source, marker):
    start = source.index(marker)
    i = source.index('{', start)
    depth, quote, escaped, line, comment = 0, None, False, False, False
    while i < len(source):
        c, n = source[i], source[i+1:i+2]
        if line:
            if c == '\n': line = False
        elif comment:
            if c == '*' and n == '/': comment = False; i += 1
        elif quote:
            if escaped: escaped = False
            elif c == '\\': escaped = True
            elif c == quote: quote = None
        elif c == '/' and n == '/': line = True; i += 1
        elif c == '/' and n == '*': comment = True; i += 1
        elif c in ('"', "'"): quote = c
        elif c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0: return source[start:i+1]
        i += 1
    raise ValueError('unbalanced source: '+marker)

names = ['SelfHostedAdminServerConfig', 'SelfHostedUserServerConfig', 'NativeServerConfig']
prefix = '''#pragma once
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include "core/utils/constants/configKeys.h"
#include "core/utils/dnsFallbackConfig.h"
namespace serverConfigUtils { constexpr int currentConfigFormatVersion = 1; }
namespace amnezia {
namespace ContainerEnumNS { enum class DockerContainer { None }; }
using namespace ContainerEnumNS;
struct ContainerConfig {
 QJsonObject toJson() const { return {}; }
 static ContainerConfig fromJson(const QJsonObject &) { return {}; }
};
namespace ContainerUtils {
 inline QString containerToString(DockerContainer) { return {}; }
 inline DockerContainer containerFromString(const QString &) { return DockerContainer::None; }
}
'''
methods = []
for name in names:
    stem = name[0].lower()+name[1:]
    header = (root / ('client/core/models/selfhosted/'+stem+'.h')).read_text(encoding='utf8')
    # Keep actual field declarations, including the descriptor, rather than a
    # test copy that could conceal a missing production model field.
    fields = header.split('struct '+name+' {', 1)[1].split('    bool ', 1)[0]
    prefix += 'struct '+name+' {\n'+fields+'\nQJsonObject toJson() const;\nstatic '+name+' fromJson(const QJsonObject &);\n};\n'
    source = (root / ('client/core/models/selfhosted/'+stem+'.cpp')).read_text(encoding='utf8')
    methods += [function(source, 'QJsonObject '+name+'::toJson('),
                function(source, name+' '+name+'::fromJson(')]
output.write_text(prefix+'\n'+'\n'.join(methods)+'\n}\n', encoding='utf8')
