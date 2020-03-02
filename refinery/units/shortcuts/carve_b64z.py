from .. import Unit
from ..pattern.carve import carve
from ..encoding.b64 import b64
from ..compression.decompress import decompress


class carve_b64z(Unit):
    """
    Carves the longest base64 encoded expression and decodes it, then applies
    the `refinery.decompress` unit to the result.
    """
    def process(self, data):
        return (carve('b64', longest=True, take=1) | b64 | decompress)(data)
