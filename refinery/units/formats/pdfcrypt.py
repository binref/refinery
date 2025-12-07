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
        password: Param[str, Arg.String(help='The password to be set.')] = '',
        user: Param[bool, Arg.Switch('-u', help='For encryption: Only set a user password.')] = False,
    ):
        super().__init__(password=password, user=user)

    def _ingest(self, data):
        pdf = self._mupdf.open(stream=data, filetype='pdf')
        if pdf.is_encrypted and (pwd := self.args.password):
            pdf.authenticate(pwd)
        if pdf.is_encrypted:
            raise ValueError('The given password was incorrect.')
        return pdf

    def process(self, data):
        with self._ingest(data) as pdf, MemoryFile() as out:
            pdf.save(out, encryption=self._mupdf.mupdf.PDF_ENCRYPT_NONE)
            return out.getvalue()

    def reverse(self, data):
        with self._ingest(data) as pdf, MemoryFile() as out:
            upwd = self.args.password
            opwd = upwd if not self.args.user else None
            pdf.save(out, encryption=self._mupdf.mupdf.PDF_ENCRYPT_AES_256, user_pw=upwd, owner_pw=opwd)
            return out.getvalue()

    @classmethod
    def handles(cls, data):
        return data[:5] == B'%PDF-'
