from __future__ import annotations

from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class pdfcrypt(Unit):
    """
    The unit removes password protection from a PDF document. If the document is encrypted, either
    the correct user or owner password must be specified to decrypt it. When the unit is operated
    in reverse, the output is encrypted using the AES-256 mode.
    """

    @Unit.Requires('pymupdf', ['formats', 'default', 'extended'])
    def _mupdf():
        import os
        for setting in ('PYMUPDF_MESSAGE', 'PYMUPDF_LOG'):
            os.environ[setting] = F'path:{os.devnull}'
        import pymupdf
        import pymupdf.mupdf
        return pymupdf

    def __init__(
        self,
        owner: Param[str, Arg.String('-w', metavar='PWD', help='Optionally specify an owner password.')] = '',
        user: Param[str, Arg.String('-u', metavar='PWD', help='Optionally specify a user password.')] = '',
    ):
        super().__init__(user=user, owner=owner)

    def _ingest(self, data):
        pdf = self._mupdf.open(stream=data, filetype='pdf')
        given = 0
        if pdf.is_encrypted and (pwd := self.args.user):
            given += 1
            pdf.authenticate(pwd)
        if pdf.is_encrypted and (pwd := self.args.owner):
            given += 1
            pdf.authenticate(pwd)
        if pdf.is_encrypted:
            msg = {
                0: 'no password was specified',
                1: 'the given password was incorrect',
                2: 'neither of the given passwords worked'
            }[given]
            raise ValueError(F'The input data is encrypted and {msg}.')
        return pdf

    def process(self, data):
        with self._ingest(data) as pdf, MemoryFile() as out:
            pdf.save(out, encryption=self._mupdf.mupdf.PDF_ENCRYPT_NONE)
            return out.getvalue()

    def reverse(self, data):
        u = self.args.user
        w = self.args.owner
        if not u and not w:
            raise ValueError('Cannot encrypt document without a password.')
        with self._ingest(data) as pdf, MemoryFile() as out:
            pdf.save(out, encryption=self._mupdf.mupdf.PDF_ENCRYPT_AES_256, user_pw=u, owner_pw=w)
            return out.getvalue()

    @classmethod
    def handles(cls, data):
        return data[:5] == B'%PDF-'
