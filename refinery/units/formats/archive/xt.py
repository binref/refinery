from __future__ import annotations

from typing import Generator, Iterable

from refinery.lib.tools import exception_to_string
from refinery.units import RefineryException
from refinery.units.formats import UnpackResult
from refinery.units.formats.archive import ArchiveUnit, MultipleArchives, PathExtractorUnit


class xt(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from archives and container formats using automatic format detection.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        out = False
        for engine in cls._handlers():
            try:
                engine_verdict = engine.handles(data)
            except Exception as error:
                cls.log_info(F'format check of {engine.name} failed:', error)
                continue
            if engine_verdict is True:
                return True
            if engine_verdict is None:
                out = None
        return out

    @staticmethod
    def _handlers():
        """
        Returns all archive handlers supported by the unit.
        """
        # units that check fixed offsets
        from refinery.units.formats.archive.xtsql import xtsql        ; yield xtsql     # noqa
        from refinery.units.formats.archive.xtdmp import xtdmp        ; yield xtdmp     # noqa
        from refinery.units.formats.archive.xttar import xttar        ; yield xttar     # noqa
        from refinery.units.formats.archive.xtiso import xtiso        ; yield xtiso     # noqa
        from refinery.units.formats.archive.xtvhd import xtvhd        ; yield xtvhd     # noqa
        from refinery.units.formats.archive.xtchm import xtchm        ; yield xtchm     # noqa
        from refinery.units.formats.archive.xtcab import xtcab        ; yield xtcab     # noqa
        from refinery.units.formats.archive.xtwim import xtwim        ; yield xtwim     # noqa
        from refinery.units.formats.archive.xtace import xtace        ; yield xtace     # noqa
        from refinery.units.formats.archive.xtmacho import xtmacho    ; yield xtmacho   # noqa
        from refinery.units.formats.archive.xtasar import xtasar      ; yield xtasar    # noqa
        from refinery.units.formats.office.xtrtf import xtrtf         ; yield xtrtf     # noqa
        from refinery.units.formats.pdf import xtpdf                  ; yield xtpdf     # noqa
        from refinery.units.formats.swf import swf                    ; yield swf       # noqa
        from refinery.units.formats.winreg import winreg              ; yield winreg    # noqa
        from refinery.units.formats.archive.xtgz import xtgz          ; yield xtgz      # noqa
        from refinery.units.formats.archive.xtcpio import xtcpio      ; yield xtcpio    # noqa
        from refinery.units.formats.archive.xtdmg import xtdmg        ; yield xtdmg     # noqa
        from refinery.units.formats.office.xtmdb import xtmdb         ; yield xtmdb     # noqa
        # units that use fixed offsets + file magic
        from refinery.units.formats.msi import xtmsi                  ; yield xtmsi     # noqa
        # units that search for markers
        from refinery.units.formats.archive.xt7z import xt7z          ; yield xt7z      # noqa
        from refinery.units.formats.archive.xtrar import xtrar        ; yield xtrar     # noqa
        from refinery.units.formats.archive.xtiex import xtiex        ; yield xtiex     # noqa
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
        from refinery.units.formats.archive.xtsf import xtsf          ; yield xtsf      # noqa
        from refinery.units.formats.archive.xtnuitka import xtnuitka  ; yield xtnuitka  # noqa
        # many things can contain a zip, so we want to check this late:
        from refinery.units.formats.archive.xtzip import xtzip        ; yield xtzip     # noqa
        # fallbacks that have to be attempted last
        from refinery.units.formats.json import xtjson                ; yield xtjson    # noqa
        from refinery.units.formats.xml import xtxml                  ; yield xtxml     # noqa
        from refinery.units.formats.html import xthtml                ; yield xthtml    # noqa
        # really obscure formats go last
        from refinery.units.formats.archive.xtrpa import xtrpa        ; yield xtrpa     # noqa

    def unpack(self, data):
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

        extraction = _Extraction(self, data, pos_args, key_args)

        if (yield from extraction.attempt(self._handlers(), False)):
            return

        fallback = extraction.fallback
        self.log_debug('fallback order:', lambda: ', '.join(h.name for h in fallback))

        if (yield from extraction.attempt(fallback, True)):
            return

        if not (errors := extraction.errors):
            raise ValueError('input data did not match any known archive format')
        for name, error in errors.items():
            self.log_info(F'error when trying to unpack with {name}:', error)
        raise RefineryException('none of the available unpackers could handle this data')


class _Extraction:
    """
    One run of `refinery.xt` over one input. It tries the handlers in order, collects the handlers
    that may apply to try them last, and keeps the reason why each handler failed.
    """
    def __init__(self, unit: xt, data, pos_args: list, key_args: dict):
        self.unit = unit
        self.data = data
        self.pos_args = pos_args
        self.key_args = key_args
        self.fallback: list[type[PathExtractorUnit]] = []
        self.errors: dict[str, str] = {}

    def attempt(self, handlers: Iterable[type[PathExtractorUnit]], is_fallback: bool) -> Generator[UnpackResult, None, bool]:
        """
        Extracts the input with the first of the given handlers that extracts anything, and returns
        whether one did.
        """
        unit = self.unit
        for handler in handlers:
            unit.CustomPathSeparator = handler.CustomPathSeparator
            unit.CustomJoinBehaviour = handler.CustomJoinBehaviour
            count = yield from self._extract(handler, is_fallback)
            if count is None:
                continue
            if count > 0:
                return True
            unit.log_debug('handler extracted zero items, continuing')
        return False

    def _extract(self, handler: type[PathExtractorUnit], is_fallback: bool) -> Generator[UnpackResult, None, int | None]:
        """
        Extracts the input with the given handler and returns the number of extracted items, or
        `None` when the handler does not apply or fails.
        """
        parent = self.unit
        data = self.data
        if is_fallback:
            verdict = True
        else:
            try:
                verdict = handler.handles(data)
            except Exception as error:
                self.errors[handler.name] = exception_to_string(error)
                if parent.log_debug():
                    raise
                parent.log_info(F'format check of {handler.name} failed:', error)
                return None
        if verdict is None:
            self.fallback.append(handler)
            return None
        if verdict is not True:
            parent.log_debug(F'rejected: {handler.name}')
            return None
        if not is_fallback:
            parent.log_info(F'accepted: {handler.name}')
        try:
            unit = handler(*self.pos_args, **self.key_args)
            unit.args.lenient = parent.args.lenient
            unit.args.quiet = parent.args.quiet
            unit.log_level = parent.log_level
        except TypeError as error:
            parent.log_debug('handler construction failed:', error)
            return None
        count = 0
        first_failure: Exception | None = None
        try:
            verified = parent.args.list
            unverified: list[UnpackResult] = []
            for filtered in unit.filter([data]):
                for item in unit.unpack(filtered):
                    if not verified:
                        try:
                            item.get_data()
                        except Exception as failure:
                            first_failure = first_failure or failure
                            unverified.append(item)
                            continue
                        verified = True
                        count += len(unverified)
                        yield from unverified
                    count += 1
                    yield item
            if first_failure is not None and not verified:
                raise first_failure
        except Exception as error:
            if not is_fallback:
                self.errors[handler.name] = exception_to_string(error)
            if isinstance(error, MultipleArchives):
                parent.log_warn(error)
            else:
                if parent.log_debug():
                    raise
                parent.log_info('handler unpacking failed:', error)
            return None
        finally:
            del first_failure
        return count
