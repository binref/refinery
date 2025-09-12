"""
Library functions for processing of Inno Setup files.
"""
from collections.abc import MutableMapping


class CaseInsensitiveDict(MutableMapping):

    def __init__(self, data=None, **kwargs):
        if isinstance(data, CaseInsensitiveDict):
            self._fold = dict(data._fold)
            self._dict = dict(data._dict)
        else:
            self._fold = dict()
            self._dict = dict()
            self.update(data or {}, **kwargs)

    def __setitem__(self, key: str, value):
        kci = key.casefold()
        self._fold[kci] = key
        self._dict[key] = value

    def __getitem__(self, key: str):
        return self._dict[self._fold[key.casefold()]]

    def __delitem__(self, key: str):
        kci = key.casefold()
        key = self._fold[kci]
        del self._fold[kci]
        del self._dict[key]

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict)

    def casefold(self):
        for kci, key in self._fold.items():
            yield (kci, self._dict[key])

    def __eq__(self, other):
        try:
            other = CaseInsensitiveDict(other)
        except Exception:
            return False
        return dict(self.casefold()) == dict(other.casefold())

    def copy(self):
        return CaseInsensitiveDict(self)

    def __repr__(self):
        return repr(self._dict)
