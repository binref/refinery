from __future__ import annotations

from hashlib import blake2b

from refinery.lib.argformats import PythonExpression
from refinery.lib.meta import metavars
from refinery.lib.types import Param, isbuffer
from refinery.units import Arg, Unit


class dedup(Unit):
    """
    Deduplicates a sequence of multiple inputs. The deduplication is limited to the current `refinery.lib.frame`.
    """
    def __init__(
        self,
        key: Param[str | None, Arg.String('key',
            help='An optional meta variable expression to deduplicate.')] = None,
        count: Param[bool, Arg.Switch('-c',
            help='Store the count of each deduplicated chunk.')] = False
    ):
        super().__init__(key=key, count=count)

    def filter(self, chunks):
        keyvar = self.args.key

        if keyvar is not None:
            def _key_from_var(chunk):
                v = PythonExpression.Evaluate(keyvar, metavars(chunk))
                if isbuffer(v):
                    v = blake2b(v, digest_size=16).digest()
                return v
            key = _key_from_var
        else:
            def _key_from_buf(chunk):
                return blake2b(chunk, digest_size=16).digest()
            key = _key_from_buf

        counts = {}
        buffer = {}
        if self.args.count:
            hashes = None
        else:
            hashes = set()

        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue

            uid = key(chunk)

            if hashes is None:
                counts[uid] = counts.get(uid, 0) + 1
                buffer.setdefault(uid, chunk)
            elif uid in hashes:
                continue
            else:
                hashes.add(uid)
                yield chunk

        if hashes is None:
            for uid, chunk in buffer.items():
                yield self.labelled(chunk, count=counts[uid])
