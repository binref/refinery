from __future__ import annotations

import re

import msgpack

from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class codebook(Unit):
    """
    Given a sequence of words (as a msgpack-encoded list of binary strings) the unit converts the
    occurrence of any of these words by a byte value representing the word's index in the sequence.
    The first word from the sequence that matches at a given offset will be used to determine this
    value. Any substrings that cannot be matched to a word in the sequence are skipped, assuming
    that they are separators.
    """
    def __init__(
        self,
        words: Param[buf, Arg.Binary(help='A list of binary strings in msgpack format.')],
    ):
        super().__init__(words=words)

    def _book(self) -> list[bytes]:
        try:
            book = msgpack.loads(self.args.words)
        except Exception:
            raise ValueError(R'The given words are not a valid msgpack buffer.')
        if not isinstance(book, list):
            raise ValueError(F'The given words are not a list, but a {type(book).__name__}.')
        if not all(isinstance(v, bytes) for v in book):
            raise ValueError(R'The given words are not all byte strings.')
        if len(book) > 256:
            raise NotImplementedError(
                R'Only code books up to 256 entries in size are currently supported.')
        return book

    def process(self, data: bytearray):
        book = self._book()
        lookup = {word: code for code, word in enumerate(book)}
        decode = re.compile(B'|'.join(re.escape(word) for word in book))
        return bytearray((lookup[x] for x in decode.findall(data)))

    def reverse(self, data: bytearray):
        book = self._book()
        return B''.join(book[b] for b in data)
