#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates the lists of toplevel domains and URL specifiers.
"""
import pprint
import os.path
import re
import requests

from refinery.lib.patterns.tlds import tlds as old_tlds

template = '''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
{variable} = {contents}
'''.lstrip()


def normalize(data, *required):
    data.update(list(required))
    return data


if __name__ == '__main__':
    session = requests.session()
    tlds = session.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt').text
    tlds = {t.strip() for t in tlds.split('\n') if '#' not in t} | {'bit', 'onion'}
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
