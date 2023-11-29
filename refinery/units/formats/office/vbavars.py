#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Union

from refinery.lib.tools import isbuffer
from refinery.units.formats import PathExtractorUnit, UnpackResult


def _txt(value: Union[bytes, str]):
    if value is None:
        return None
    if not isinstance(value, str):
        value = value.decode(vbavars.codec)
    return value


def _bin(value):
    if value is None:
        return None
    if not isbuffer(value):
        if not isinstance(value, str):
            value = str(value)
        value = value.encode(vbavars.codec)
    return value


class vbavars(PathExtractorUnit):
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
        for (path, stream, vars) in parser.extract_form_strings_extended():
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
                yield UnpackResult(F'{path!s}/{stream!s}/{name}.{ext}', value)
