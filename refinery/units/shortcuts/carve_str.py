import refinery as r


class carve_str(r.Unit):
    """
    Carves the longest string expression and removes the surrounding quotes.
    """
    def process(self, data):
        return (r.carve('-lt1', 'string') | r.snip('1:-1'))(data)
