import refinery as r


class carve_b64(r.Unit):
    """
    Carves the longest base64 encoded expression and decodes it.
    """
    def process(self, data):
        return (r.carve('-lt1', 'b64') | r.b64)(data)
