"""Compile actual production stream builder with real config types, without SSH/GUI."""
from pathlib import Path
import sys

root, output = map(Path, sys.argv[1:3])
source = (root / 'client/core/configurators/xrayConfigurator.cpp').read_text(encoding='utf8')

def function(marker):
    start = source.index(marker)
    brace = source.index('{', start)
    i, depth, quote, escape, line, comment = brace + 1, 1, None, False, False, False
    while depth:
        c, n = source[i], source[i + 1:i + 2]
        if line:
            if c == '\n': line = False
        elif comment:
            if c == '*' and n == '/': comment = False; i += 1
        elif quote:
            if escape: escape = False
            elif c == '\\': escape = True
            elif c == quote: quote = None
        elif c == '/' and n == '/': line = True; i += 1
        elif c == '/' and n == '*': comment = True; i += 1
        elif c in ('"', "'"): quote = c
        elif c == '{': depth += 1
        elif c == '}': depth -= 1
        i += 1
    return source[start:i]

helpers = ['QString normalizeXhttpMode(', 'QString normalizeSessionSeqPlacement(',
           'QString normalizeUplinkDataPlacement(', 'QString normalizeXPaddingPlacement(',
           'QString normalizeXPaddingMethod(', 'QString makeRangeString(',
           'void putIntRangeIfAny(', 'QString effectiveSecurity(']
prefix = '''#pragma once
#include <QJsonArray>
#include <QJsonObject>
#include "core/models/protocols/xrayProtocolConfig.h"
using namespace amnezia;
class XrayConfigurator {
public:
    QJsonObject buildStreamSettings(const amnezia::XrayServerConfig &, const QString &) const;
};
'''
output.write_text(prefix + '\nnamespace {\n' + '\n'.join(function(m) for m in helpers)
                  + '\n}\n' + function('QJsonObject XrayConfigurator::buildStreamSettings('), encoding='utf8')
