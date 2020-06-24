#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File type related functions.
"""
import re
from .magic import magic, magicparse


class NoMagicAvailable(ModuleNotFoundError):
    pass


def file_extension(subtype, default='bin'):
    try:
        return {
            'octet-stream'                : 'bin',
            'plain'                       : 'txt',
            'javascript'                  : 'js',
            'java-archive'                : 'jar',
            'svg+xml'                     : 'svg',
            'x-icon'                      : 'ico',
            'wave'                        : 'wav',
            'x-pn-wav'                    : 'wav',
            'x-ms-wim'                    : 'wim',
            'vnd.android.package-archive' : 'apk',
            'vnd.ms-cab-compressed'       : 'cab',
            'x-apple-diskimage'           : 'dmg',
        }[subtype]
    except KeyError:
        if 'gzip' in subtype:
            return 'gz'
        xtype_match = re.match(
            r'^x-(\w{2,4})(-compressed)?$',
            subtype,
            re.IGNORECASE
        )
        if xtype_match:
            return xtype_match[1]
        if len(subtype) < 6 and re.match('[a-z]+', subtype):
            return subtype
        return default


def file_extension_from_data(data, default='bin'):

    if not magic:
        raise NoMagicAvailable

    if not isinstance(data, bytes):
        data = bytes(data)

    mime = magicparse(data, mime=True)
    mime = mime.split(';')[0].lower()
    maintype, subtype = mime.split('/')

    if subtype == 'x-dosexec':
        description = magicparse(data)
        if re.search('executable', description):
            return 'dll' if '(DLL)' in description else 'exe'

    extension = file_extension(subtype, default)

    if extension == 'gz':
        import gzip
        ungz = gzip.decompress(data)
        extension = F'{file_extension_from_data(ungz, default)}.gz'

    return extension
