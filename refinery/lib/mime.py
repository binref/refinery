#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File type related functions.
"""
import functools

from .magic import magic, magicparse


class NoMagicAvailable(ModuleNotFoundError):
    pass


FileTypeMap = {
    'applicaiton/x-bytecode.python' : 'pyc',
    'application/acad'              : 'dwg',
    'application/arj'               : 'arj',
    'application/book'              : 'book',
    'application/dos-exe'           : 'exe',
    'application/drafting'          : 'drw',
    'application/dxf'               : 'dxf',
    'application/ecmascript'        : 'js',
    'application/epub+zip'          : 'epub',
    'application/excel'             : 'xls',
    'application/exe'               : 'exe',
    'application/gnutar'            : 'tgz',
    'application/gzip'              : 'gz',
    'application/hlp'               : 'hlp',
    'application/inf'               : 'inf',
    'application/java-archive'      : 'jar',
    'application/java-byte-code'    : 'class',
    'application/java'              : 'class',
    'application/javascript'        : 'js',
    'application/json'              : 'json',
    'application/ld+json'           : 'jsonld',
    'application/lha'               : 'lha',
    'application/lzx'               : 'lzx',
    'application/mac-binary'        : 'bin',
    'application/mac-compactpro'    : 'cpt',
    'application/macbinary'         : 'bin',
    'application/mime'              : 'aps',
    'application/msdos-windows'     : 'exe',
    'application/mspowerpoint'      : 'ppt',
    'application/msword'            : 'doc',
    'application/octet-stream'      : 'bin',
    'application/ogg'               : 'ogg',
    'application/pdf'               : 'pdf',
    'application/plain'             : 'text',
    'application/postscript'        : 'ps',
    'application/powerpoint'        : 'ppt',
    'application/rtf'               : 'rtf',
    'application/vnd.amazon.ebook'  : 'azw',
    'application/vnd.apple.installer+xml' : 'mpkg',
    'application/vnd.hp-pcl'        : 'pcl',
    'application/vnd.lotus-1-2-3'   : '123',
    'application/vnd.mozilla.xul+xml' : 'xul',
    'application/vnd.ms-excel'      : 'xls',
    'application/vnd.ms-fontobject' : 'eot',
    'application/vnd.ms-powerpoint' : 'ppt',
    'application/vnd.oasis.opendocument.presentation' : 'odp',
    'application/vnd.oasis.opendocument.spreadsheet' : 'ods',
    'application/vnd.oasis.opendocument.text' : 'odt',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation' : 'pptx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' : 'xlsx',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document' : 'docx',
    'application/vnd.rar'           : 'rar',
    'application/vnd.rn-realmedia'  : 'rm',
    'application/vnd.visio'         : 'vsd',
    'application/vocaltec-media-desc' : 'vmd',
    'application/x-7z-compressed'   : '7z',
    'application/x-abiword'         : 'abw',
    'application/x-binary'          : 'bin',
    'application/x-bsh'             : 'sh',
    'application/x-bzip'            : 'bz',
    'application/x-bzip2'           : 'bz2',
    'application/x-cdlink'          : 'vcd',
    'application/x-compactpro'      : 'cpt',
    'application/x-compress'        : 'z',
    'application/x-compressed'      : 'gz',
    'application/x-cpt'             : 'cpt',
    'application/x-csh'             : 'csh',
    'application/x-dosexec'         : 'exe',
    'application/x-dvi'             : 'dvi',
    'application/x-excel'           : 'xls',
    'application/x-exe'             : 'exe',
    'application/x-freearc'         : 'arc',
    'application/x-gzip'            : 'gz',
    'application/x-helpfile'        : 'hlp',
    'application/x-httpd-php'       : 'php',
    'application/x-java-class'      : 'class',
    'application/x-java-commerce'   : 'jcm',
    'application/x-javascript'      : 'js',
    'application/x-latex'           : 'latex',
    'application/x-lha'             : 'lha',
    'application/x-lisp'            : 'lsp',
    'application/x-lzh'             : 'lzh',
    'application/x-lzx'             : 'lzx',
    'application/x-macbinary'       : 'bin',
    'application/x-midi'            : 'mid',
    'application/x-mplayer2'        : 'asx',
    'application/x-msdos-program'   : 'exe',
    'application/x-msdownload'      : 'exe',
    'application/x-msexcel'         : 'xls',
    'application/x-mspowerpoint'    : 'ppt',
    'application/x-navi-animation'  : 'ani',
    'application/x-pcl'             : 'pcl',
    'application/x-pointplus'       : 'css',
    'application/x-rtf'             : 'rtf',
    'application/x-sh'              : 'sh',
    'application/x-shar'            : 'sh',
    'application/x-shockwave-flash' : 'swf',
    'application/x-tar'             : 'tar',
    'application/x-tcl'             : 'tcl',
    'application/x-troff-man'       : 'man',
    'application/x-troff-msvideo'   : 'avi',
    'application/x-visio'           : 'vsd',
    'application/x-vrml'            : 'vrml',
    'application/x-winexe'          : 'exe',
    'application/x-winhelp'         : 'hlp',
    'application/x-zip-compressed'  : 'zip',
    'application/x-zoo'             : 'zoo',
    'application/xhtml+xml'         : 'xhtml',
    'application/xml'               : 'xml',
    'application/zip'               : 'zip',
    'audio/aac'                     : 'aac',
    'audio/aiff'                    : 'aiff',
    'audio/basic'                   : 'au',
    'audio/midi'                    : 'mid',
    'audio/mod'                     : 'mod',
    'audio/mpeg'                    : 'mpg',
    'audio/mpeg3'                   : 'mp3',
    'audio/ogg'                     : 'ogg',
    'audio/opus'                    : 'opus',
    'audio/wav'                     : 'wav',
    'audio/webm'                    : 'webm',
    'audio/x-aiff'                  : 'aiff',
    'audio/x-au'                    : 'au',
    'audio/x-jam'                   : 'jam',
    'audio/x-mid'                   : 'mid',
    'audio/x-midi'                  : 'mid',
    'audio/x-mod'                   : 'mod',
    'audio/x-mpeg-3'                : 'mp3',
    'audio/x-mpeg'                  : 'mp2',
    'audio/x-mpequrl'               : 'm3u',
    'audio/x-pn-realaudio-plugin'   : 'ra',
    'audio/x-pn-realaudio'          : 'rm',
    'audio/x-realaudio'             : 'ra',
    'audio/x-wav'                   : 'wav',
    'audio/xm'                      : 'xm',
    'font/otf'                      : 'otf',
    'font/ttf'                      : 'ttf',
    'font/woff'                     : 'woff',
    'font/woff2'                    : 'woff2',
    'image/bmp'                     : 'bmp',
    'image/gif'                     : 'gif',
    'image/jpeg'                    : 'jpg',
    'image/pict'                    : 'pic',
    'image/pjpeg'                   : 'jpg',
    'image/png'                     : 'png',
    'image/svg+xml'                 : 'svg',
    'image/tiff'                    : 'tif',
    'image/vnd.dwg'                 : 'dwg',
    'image/vnd.microsoft.icon'      : 'ico',
    'image/webp'                    : 'webp',
    'image/x-3ds'                   : '3ds',
    'image/x-dwg'                   : 'dwg',
    'image/x-icon'                  : 'ico',
    'image/x-jg'                    : 'art',
    'image/x-jps'                   : 'jps',
    'image/x-pcx'                   : 'pcx',
    'image/x-pict'                  : 'pct',
    'image/x-quicktime'             : 'qtif',
    'image/x-tiff'                  : 'tif',
    'image/x-windows-bmp'           : 'bmp',
    'image/x-xpixmap'               : 'pm',
    'model/vrml'                    : 'vrml',
    'multipart/x-gzip'              : 'gz',
    'multipart/x-zip'               : 'zip',
    'music/crescendo'               : 'mid',
    'text/asp'                      : 'asp',
    'text/calendar'                 : 'ics',
    'text/css'                      : 'css',
    'text/csv'                      : 'csv',
    'text/ecmascript'               : 'js',
    'text/html'                     : 'html',
    'text/javascript'               : 'js',
    'text/pascal'                   : 'pas',
    'text/plain'                    : 'txt',
    'text/richtext'                 : 'rtf',
    'text/sgml'                     : 'sgml',
    'text/uri-list'                 : 'uri',
    'text/webviewhtml'              : 'htt',
    'text/x-asm'                    : 'asm',
    'text/x-c'                      : 'c',
    'text/x-component'              : 'htc',
    'text/x-h'                      : 'h',
    'text/x-java-source'            : 'java',
    'text/x-script.lisp'            : 'lsp',
    'text/x-script.perl-module'     : 'pm',
    'text/x-script.perl'            : 'pl',
    'text/x-script.phyton'          : 'py',
    'text/x-script.sh'              : 'sh',
    'text/x-script.tcl'             : 'tcl',
    'text/x-scriptzsh'              : 'zsh',
    'text/x-server-parsed-html'     : 'shtml',
    'text/x-sgml'                   : 'sgml',
    'text/xml'                      : 'xml',
    'video/3gpp'                    : '3gp',
    'video/3gpp2'                   : '3g2',
    'video/avi'                     : 'avi',
    'video/dl'                      : 'dl',
    'video/mp2t'                    : 'ts',
    'video/mp4'                     : 'mp4',
    'video/mpeg'                    : 'mpeg',
    'video/msvideo'                 : 'avi',
    'video/ogg'                     : 'ogg',
    'video/quicktime'               : 'mov',
    'video/vnd.rn-realvideo'        : 'rv',
    'video/webm'                    : 'webm',
    'video/x-dl'                    : 'dl',
    'video/x-dv'                    : 'dif',
    'video/x-mpeg'                  : 'mp4',
    'video/x-mpeq2a'                : 'mp2',
    'video/x-ms-asf-plugin'         : 'asx',
    'video/x-ms-asf'                : 'asf',
    'video/x-msvideo'               : 'avi',
    'video/x-sgi-movie'             : 'movie',
    'vms/exe'                       : 'exe',
    'windows/metafile'              : 'wmf',
    'x-conference/x-cooltalk'       : 'ice',
    'x-music/x-midi'                : 'mid',
    'x-world/x-3dmf'                : '3dmf',
    'x-world/x-vrml'                : 'vrml',
}


def file_extension(mime, default='bin'):
    return FileTypeMap.get(mime, default)


class FileMagicInfo:
    extension: str
    description: str
    mime: str

    def __init__(self, data, default='bin'):
        if not magic:
            raise NoMagicAvailable
        if not isinstance(data, bytes):
            data = bytes(data)
        mime = magicparse(data, mime=True)
        self.mime = mime.split(';')[0].lower()
        self.description = magicparse(data)
        try:
            extension = FileTypeMap[self.mime]
        except KeyError:
            extension = default
        if self.description == 'Microsoft OOXML':
            extension = 'docx'
        if extension == 'exe':
            extension = 'dll' if '(DLL)' in self.description else 'exe'
        else:
            compression = dict(gz='gzip').get(extension, extension)
            if compression in ('gzip', 'bz2'):
                from importlib import import_module
                decompressor = import_module(compression)
                decompressed = decompressor.decompress(data)
                inner = FileMagicInfo(decompressed, default).extension
                extension = F'{inner}.{extension}'
        self.extension = extension


@functools.lru_cache(maxsize=None)
def get_cached_file_magic_info(data):
    return FileMagicInfo(data)
