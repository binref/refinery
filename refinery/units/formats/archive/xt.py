#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import List, Optional, Type

from refinery.units.formats.archive import ArchiveUnit, MultipleArchives
from refinery.units import RefineryException


class xt(ArchiveUnit):
    """
    Extract files from archives. The unit tries to identify the archive format and use the
    correct extractor.
    """
    @classmethod
    def handles(cls, data: bytearray) -> Optional[bool]:
        out = False
        for engine in cls.handlers():
            engine_verdict = engine.handles(data)
            if engine_verdict is True:
                return True
            if engine_verdict is None:
                out = None
        return out

    @staticmethod
    def handlers():
        """
        Returns all archive handlers supported by the unit.
        """
        from refinery.units.formats.office.xtone import xtone
        yield xtone
        from refinery.units.formats.archive.xtgz import xtgz
        yield xtgz
        from refinery.units.formats.email import xtmail
        yield xtmail
        from refinery.units.formats.pdf import xtpdf
        yield xtpdf
        from refinery.units.formats.archive.xtasar import xtasar
        yield xtasar
        from refinery.units.formats.office.xtrtf import xtrtf
        yield xtrtf
        from refinery.units.formats.archive.xtzpaq import xtzpaq
        yield xtzpaq
        from refinery.units.formats.pe.dotnet.dnsfx import dnsfx
        yield dnsfx
        from refinery.units.formats.archive.xtnsis import xtnsis
        yield xtnsis
        from refinery.units.formats.archive.xtnode import xtnode
        yield xtnode
        from refinery.units.formats.archive.xtace import xtace
        yield xtace
        from refinery.units.formats.archive.xtcab import xtcab
        yield xtcab
        from refinery.units.formats.archive.xtcpio import xtcpio
        yield xtcpio
        from refinery.units.formats.archive.xtiso import xtiso
        yield xtiso
        from refinery.units.formats.archive.xtpyi import xtpyi
        yield xtpyi
        from refinery.units.formats.archive.xttar import xttar
        yield xttar
        from refinery.units.formats.archive.xtiss import xtiss
        yield xtiss
        from refinery.units.formats.archive.xtzip import xtzip
        yield xtzip
        from refinery.units.formats.archive.xt7z import xt7z
        yield xt7z
        from refinery.units.formats.msi import xtmsi
        yield xtmsi
        from refinery.units.formats.archive.xtnuitka import xtnuitka
        yield xtnuitka
        from refinery.units.formats.office.xtdoc import xtdoc
        yield xtdoc
        from refinery.units.formats.json import xtjson
        yield xtjson
        from refinery.units.formats.exe.vsect import vsect
        yield vsect

    def unpack(self, data):
        fallback: List[Type[ArchiveUnit]] = []
        errors = {}
        pos_args = self.args.paths
        key_args = dict(
            list=self.args.list,
            path=self.args.path,
            date=self.args.date,
            join_path=self.args.join,
            drop_path=self.args.drop,
        )
        if self.args.pwd:
            key_args.update(pwd=self.args.pwd)
        if self.args.regex:
            key_args.update(regex=self.args.regex)

        class unpacker:
            unit = self

            def __init__(self, handler: Type[ArchiveUnit], fallback: bool):
                self.success = False
                self.handler = handler
                self.fallback = fallback

            def __iter__(self):
                handler = self.handler
                if self.fallback:
                    verdict = True
                else:
                    verdict = handler.handles(data)
                if verdict is False:
                    self.unit.log_info(F'rejected: {handler.name}')
                elif verdict is True:
                    if not self.fallback:
                        self.unit.log_info(F'accepted: {handler.name}')
                    try:
                        unit = handler(*pos_args, **key_args)
                        unit.args.lenient = self.unit.args.lenient
                        unit.args.quiet = self.unit.args.quiet
                    except TypeError as error:
                        self.unit.log_debug('handler construction failed:', error)
                        return
                    try:
                        for item in unit.unpack(data):
                            item.get_data()
                            yield item
                    except Exception as error:
                        if not self.fallback:
                            errors[handler.name] = error
                        if isinstance(error, MultipleArchives):
                            self.unit.log_warn(error)
                        else:
                            self.unit.log_debug('handler unpacking failed:', error)
                    else:
                        self.success = True
                elif verdict is None:
                    fallback.append(handler)

        for handler in self.handlers():
            self._custom_path_separator = handler._custom_path_separator
            it = unpacker(handler, fallback=False)
            yield from it
            if it.success:
                return

        self.log_debug('fallback order:', lambda: ', '.join(h.name for h in fallback))

        for handler in fallback:
            it = unpacker(handler, fallback=True)
            yield from it
            if it.success:
                return

        if not errors:
            raise ValueError('input data did not match any known archive format')
        for name, error in errors.items():
            self.log_info(F'error when trying to unpack with {name}:', error)
        raise RefineryException('none of the available unpackers could handle this data')
