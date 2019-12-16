import refinery as r


class carve_b64z(r.Unit):
    """
    Carves the longest base64 encoded expression and decodes it, then applies
    the `refinery.decompress` unit to the result.
    """
    def process(self, data):
        return (r.carve('-lt1', 'b64') | r.b64 | r.decompress)(data)
