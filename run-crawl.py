#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates the lists of toplevel domains and URL specifiers.
"""
import requests
import pprint
import os.path
import re

template = '''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
{variable} = {contents}
'''


def normalize(data, *required):
    data.extend(list(required))
    data = [item.lower() for item in data if item]
    data = [re.escape(item) for item in set(data)]
    data.sort()
    data.sort(key=len, reverse=True)
    return data


if __name__ == '__main__':
    session = requests.session()

    print('-- collectiong tlds')
    tlds = session.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt').text
    tlds = [t.strip() for t in tlds.split('\n') if '#' not in t]
    tlds = normalize(tlds, 'bit')

    with open(os.path.join('.', 'refinery', 'lib', 'patterns', 'tlds.py'), 'w') as stream:
        stream.write(template.format(
            variable='tlds',
            contents=pprint.pformat(tlds)
        ))

    print('-- collectiong schemes')
    schemes = session.get('https://www.iana.org/assignments/uri-schemes/uri-schemes-1.csv').text
    schemes = re.findall(R'^([\w\-\.]+),', schemes, re.MULTILINE | re.IGNORECASE)
    schemes = normalize(schemes, 'http', 'https', 'ftp', 'imap', 'file', 'mailto')

    with open(os.path.join('.', 'refinery', 'lib', 'patterns', 'schemes.py'), 'w') as stream:
        stream.write(template.format(
            variable='schemes',
            contents=pprint.pformat(schemes)
        ))
