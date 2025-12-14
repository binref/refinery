from __future__ import annotations

from refinery.units import RefineryException
from refinery.units.formats.archive import ArchiveUnit, MultipleArchives, PathExtractorUnit


class xt(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    This unit generically extracts files from archives. It attempts to identify the archive format
    and use the corresponding specific extractor from among the ones implemented in refinery.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
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
        # units that check fixed offsets
        from refinery.units.formats.archive.xtsql import xtsql        ; yield xtsql     # noqa
        from refinery.units.formats.archive.xtdmp import xtdmp        ; yield xtdmp     # noqa
        from refinery.units.formats.archive.xttar import xttar        ; yield xttar     # noqa
        from refinery.units.formats.archive.xtiso import xtiso        ; yield xtiso     # noqa
        from refinery.units.formats.archive.xtchm import xtchm        ; yield xtchm     # noqa
        from refinery.units.formats.archive.xtcab import xtcab        ; yield xtcab     # noqa
        from refinery.units.formats.archive.xtace import xtace        ; yield xtace     # noqa
        from refinery.units.formats.archive.xtmacho import xtmacho    ; yield xtmacho   # noqa
        from refinery.units.formats.archive.xtasar import xtasar      ; yield xtasar    # noqa
        from refinery.units.formats.office.xtrtf import xtrtf         ; yield xtrtf     # noqa
        from refinery.units.formats.pdf import xtpdf                  ; yield xtpdf     # noqa
        from refinery.units.formats.winreg import winreg              ; yield winreg    # noqa
        from refinery.units.formats.archive.xtgz import xtgz          ; yield xtgz      # noqa
        from refinery.units.formats.archive.xtcpio import xtcpio      ; yield xtcpio    # noqa
        # units that use fixed offsets + file magic
        from refinery.units.formats.msi import xtmsi                  ; yield xtmsi     # noqa
        # units that search for markers
        from refinery.units.formats.archive.xt7z import xt7z          ; yield xt7z      # noqa
        from refinery.units.formats.archive.xtzip import xtzip        ; yield xtzip     # noqa
        from refinery.units.formats.pe.dotnet.dnsfx import dnsfx      ; yield dnsfx     # noqa
        from refinery.units.formats.archive.xtinno import xtinno      ; yield xtinno    # noqa
        from refinery.units.formats.archive.xtiss import xtiss        ; yield xtiss     # noqa
        from refinery.units.formats.archive.xtnsis import xtnsis      ; yield xtnsis    # noqa
        from refinery.units.formats.archive.xtpyi import xtpyi        ; yield xtpyi     # noqa
        from refinery.units.formats.a3x import a3x                    ; yield a3x       # noqa
        from refinery.units.formats.archive.xtnode import xtnode      ; yield xtnode    # noqa
        from refinery.units.formats.archive.xtzpaq import xtzpaq      ; yield xtzpaq    # noqa
        from refinery.units.formats.email import xtmail               ; yield xtmail    # noqa
        from refinery.units.formats.office.xtone import xtone         ; yield xtone     # noqa
        from refinery.units.formats.office.xtdoc import xtdoc         ; yield xtdoc     # noqa
        # units that implement more complex parsing / searching:
        from refinery.units.formats.archive.xtsim import xtsim        ; yield xtsim     # noqa
        from refinery.units.formats.archive.xtnuitka import xtnuitka  ; yield xtnuitka  # noqa
        # fallbacks that have to be attempted last
        from refinery.units.formats.json import xtjson                ; yield xtjson    # noqa
        from refinery.units.formats.xml import xtxml                  ; yield xtxml     # noqa
        from refinery.units.formats.html import xthtml                ; yield xthtml    # noqa
        # really obscure formats go last
        from refinery.units.formats.archive.xtrpa import xtrpa        ; yield xtrpa     # noqa

    def unpack(self, data):
        fallback: list[type[PathExtractorUnit]] = []
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

            def __init__(self, handler: type[PathExtractorUnit], fallback: bool):
                self.success = False
                self.handler = handler
                self.fallback = fallback
                self.count = 0

            def __iter__(self):
                handler = self.handler
                if self.fallback:
                    verdict = True
                else:
                    verdict = handler.handles(data)
                if verdict is False:
                    self.unit.log_debug(F'rejected: {handler.name}')
                elif verdict is True:
                    if not self.fallback:
                        self.unit.log_info(F'accepted: {handler.name}')
                    try:
                        unit = handler(*pos_args, **key_args)
                        unit.args.lenient = self.unit.args.lenient
                        unit.args.quiet = self.unit.args.quiet
                        unit.log_level = self.unit.log_level
                    except TypeError as error:
                        self.unit.log_debug('handler construction failed:', error)
                        return
                    try:
                        test_unpack = not self.unit.args.list
                        for filtered in unit.filter([data]):
                            for item in unit.unpack(filtered):
                                if test_unpack:
                                    item.get_data()
                                    test_unpack = False
                                self.count += 1
                                yield item
                    except Exception as error:
                        if not self.fallback:
                            errors[handler.name] = error
                        if isinstance(error, MultipleArchives):
                            self.unit.log_warn(error)
                        else:
                            if self.unit.log_debug():
                                raise error
                            self.unit.log_info('handler unpacking failed:', error)
                    else:
                        self.success = True
                elif verdict is None:
                    fallback.append(handler)

        extracted = 0

        for handler in self.handlers():
            self.CustomPathSeparator = handler.CustomPathSeparator
            self.CustomJoinBehaviour = handler.CustomJoinBehaviour
            it = unpacker(handler, fallback=False)
            yield from it
            if it.success:
                extracted += it.count
                if extracted != 0:
                    break
                self.log_debug('handler extracted zero items, continuing')

        if extracted > 0:
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
