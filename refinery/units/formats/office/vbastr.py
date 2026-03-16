from __future__ import annotations

import codecs

from refinery.lib.ole.forms import OleFormParsingError
from refinery.lib.ole.vba import FileOpenError, VBAParser
from refinery.lib.types import isbuffer
from refinery.units.formats import PathExtractorUnit, UnpackResult


def _txt(value: bytes | str):
    if value is None:
        return None
    if not isinstance(value, str):
        value = codecs.decode(value, vbastr.codec)
    return value


def _bin(value):
    if value is None:
        return None
    if not isbuffer(value):
        if not isinstance(value, str):
            value = str(value)
        value = value.encode(vbastr.codec)
    return value


class vbastr(PathExtractorUnit):
    """
    Extract VBA macro variables from Office documents.

    The items are extracted in a directory hierarchy that specifies their corresponding OLE
    stream. The stem of their file name is the same as the variable's name. The variable
    can define a caption, a control tip text, and a value; the unit extracts these with the
    synthesized file extension "cap", "tip", and "val", respectively.
    """
    @classmethod
    def handles(cls, data) -> bool:
        return data[:4] == B'\xD0\xCF\x11\xE0'

    def unpack(self, value):
        try:
            parser = VBAParser(bytes(value))
        except FileOpenError:
            raise ValueError('Input data not recognized by VBA parser')
        try:
            for fv in parser.extract_form_strings_extended():
                if not fv.variable:
                    continue
                name = _txt(fv.variable['name'])
                for ext, key in {
                    'cap': 'caption',
                    'tip': 'control_tip_text',
                    'val': 'value',
                }.items():
                    value = _bin(fv.variable.get(key))
                    if not value:
                        continue
                    yield UnpackResult(F'{fv.filename!s}/{name!s}/{name}.{ext}', value)
        except OleFormParsingError as error:
            from collections import Counter
            self.log_debug(str(error))
            self.log_info('extended form extraction failed with error; falling back to simple method')
            form_strings = list(parser.extract_form_strings())
            name_counter = Counter(fs.stream_path for fs in form_strings)
            dedup = Counter()
            for fs in form_strings:
                if fs.value is None:
                    continue
                if name_counter[fs.stream_path] > 1:
                    dedup[fs.stream_path] += 1
                    stream_name = F'{fs.stream_path!s}.v{dedup[fs.stream_path]}'
                else:
                    stream_name = fs.stream_path
                yield UnpackResult(F'{fs.filename!s}/{stream_name!s}.val', _bin(fs.value))
