from __future__ import annotations

from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class officecrypt(Unit):
    """
    Decrypt encrypted Microsoft Office documents, including Word, Excel, and PowerPoint.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import Fmt, get_microsoft_format
        if get_microsoft_format(data) == Fmt.OFFICECRYPT:
            return True

    def __init__(self, password: Param[buf, Arg.Binary(help=(
        'The document password. By default, the Excel default password "{default}" is used.'
    ))] = b'VelvetSweatshop'):
        super().__init__(password=password)

    def process(self, data):
        from refinery.lib.ole.crypto import OfficeFile
        password: bytes = self.args.password
        with MemoryFile(data) as stream:
            doc = OfficeFile(stream)
            if not doc.is_encrypted():
                self.log_warn('the document is not encrypted; returning input')
                return data
            if password:
                doc.load_key(password=password.decode(self.codec))
            with MemoryFile(bytearray()) as output:
                doc.decrypt(output)
                return output.getvalue()
