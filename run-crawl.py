#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates the lists of toplevel domains and URL specifiers.
"""
import pprint
import os.path
import re
import io
import requests
import zipfile
import json

from refinery.lib import xml
from refinery.lib.patterns.tlds import tlds as old_tlds

template = '''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
{variable} = {contents}
'''.lstrip()


def normalize(data, *required):
    data.update(list(required))
    return data


def crawl_tlds():
    session = requests.session()
    tlds = session.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt').text
    tlds = {t.strip() for t in tlds.split('\n') if '#' not in t} | {'bit', 'onion', 'sys', 'bazar', 'coin'}
    tlds = {item.lower() for item in tlds if item}
    tlds = {re.escape(item) for item in set(tlds)}
    tlds.update(old_tlds)
    tlds = list(tlds)
    tlds.sort()
    tlds.sort(key=len, reverse=True)
    with open(os.path.join('.', 'refinery', 'lib', 'patterns', 'tlds.py'), 'w') as stream:
        stream.write(template.format(
            variable='tlds',
            contents=pprint.pformat(tlds)
        ))


def crawl_rich():
    session = requests.session()
    with io.BytesIO(session.get('https://www.winitor.com/tools/pestudio/current/pestudio.zip').content) as fd:
        archive = zipfile.ZipFile(fd)
        for info in archive.infolist():
            fn = info.filename
            if fn.endswith('.xml') and 'rich' in fn:
                rich = xml.parse(archive.read(info.filename))
                break
    while len(rich.children) == 1:
        rich = rich.children[0]
    r = {}
    ide = {item['id']: item.content.strip() for item in rich.child('ide').children}
    r['pid'] = {F'{int(item["id"],00):04X}': item.content.strip() for item in rich.child('prodId').children}
    r['ver'] = {
        F'{int(item["value"],10):04X}': {
            'ide': ide[item['ide']],
            'ver': item.content.strip()
        }
        for item in rich.child('version')
    }

    dishather = session.get('https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt').text
    for match in re.finditer(r'(?im)^(?P<value>[a-f0-9]{8})\s\[...\]\s(?P<description>.*)$', dishather):
        value = int(match['value'], 16)
        code = F'{value&0xFFFF:04X}'
        if code not in r['ver']:
            r['ver'][code] = {'ide': match['description']}

    with open(os.path.join('.', 'refinery', 'data', 'rich.json'), 'w') as stream:
        json.dump(r, stream, indent=2)


def main():
    crawl_tlds()
    crawl_rich()


if __name__ == '__main__':
    main()