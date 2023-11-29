#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Union

from refinery.lib.tools import isbuffer
from refinery.units.formats import PathExtractorUnit, UnpackResult


def _txt(value: Union[bytes, str]):
    if value is None:
        return None
    if not isinstance(value, str):
        value = value.decode(vbastr.codec)
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
    Extract VBA macro variables from Office documents. The items are extracted in a directory
    hierarchy that specifies their corresponding OLE stream. The stem of their file name is the
    same as the variable's name. The variable can define a caption, a control tip text, and a
    value; the unit extracts these with the synthesized file extension "cap", "tip", and "val",
    respectively.
    """
    @PathExtractorUnit.Requires('oletools', 'formats', 'office')
    def _olevba():
        from oletools import olevba
        return olevba

    def unpack(self, value):
        try:
            parser = self._olevba.VBA_Parser('.', data=bytes(value), relaxed=True)
        except self._olevba.FileOpenError:
            raise ValueError('Input data not recognized by VBA parser')
        try:
            for path, name, vars in parser.extract_form_strings_extended():
                if not vars:
                    continue
                name = _txt(vars['name'])
                for ext, key in {
                    'cap': 'caption',
                    'tip': 'control_tip_text',
                    'val': 'value',
                }.items():
                    value = _bin(vars.get(key))
                    if not value:
                        continue
                    yield UnpackResult(F'{path!s}/{name!s}/{name}.{ext}', value)
        except self._olevba.oleform.OleFormParsingError as error:
            from collections import Counter
            self.log_debug(str(error))
            self.log_info('extended form extraction failed with error; falling back to simple method')
            form_strings = list(parser.extract_form_strings())
            name_counter = Counter(name for _, name, _ in form_strings)
            dedup = Counter()
            for path, name, string in form_strings:
                if string is None:
                    continue
                if name_counter[name] > 1:
                    dedup[name] += 1
                    name = F'{name!s}.v{dedup[name]}'
                yield UnpackResult(F'{path!s}/{name!s}.val', _bin(string))
