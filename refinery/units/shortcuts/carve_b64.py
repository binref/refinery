from .. import Unit
from ..pattern.carve import carve
from ..encoding.b64 import b64


class carve_b64(Unit):
    """
    Carves the longest base64 encoded expression and decodes it.
    """
    def process(self, data):
        return (carve('b64', longest=True, take=1) | b64)(data)
