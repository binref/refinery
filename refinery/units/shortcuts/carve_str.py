from .. import Unit
from ..pattern.carve import carve


class carve_str(Unit):
    """
    Carves the longest string expression and removes the surrounding quotes.
    """
    def process(self, data):
        return carve('string', longest=True, take=1)(data)[1:-1]
