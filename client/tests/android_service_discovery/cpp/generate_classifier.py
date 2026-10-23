"""Extract the actual pure production classifier; no application/backend code."""
from pathlib import Path
import hashlib
import json
import sys
source=Path(sys.argv[1]).read_bytes()
text=source.decode('utf-8')
needle='static QString androidDiscoveryComponent(const QJsonObject &configuration)'
if text.count(needle)!=1:
    raise SystemExit('expected one exact production classifier')
begin=text.index(needle)
brace=text.index('{',begin)
depth=1
at=brace+1
while depth and at<len(text):
    if text[at]=='{': depth+=1
    if text[at]=='}': depth-=1
    at+=1
if depth:
    raise SystemExit('unclosed classifier')
fragment=text[begin:at]
Path(sys.argv[2]).write_text(fragment+'\n',encoding='utf-8')
Path(sys.argv[2]+'.json').write_text(json.dumps({'source_sha256':hashlib.sha256(source).hexdigest(),'fragment_sha256':hashlib.sha256(fragment.encode()).hexdigest(),'source':'client/vpnConnection.cpp','function':'androidDiscoveryComponent','seam':'pure actual function only; no JNI/app/backend'},indent=2)+'\n')
