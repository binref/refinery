from __future__ import annotations

from hashlib import md5

from refinery.lib.argformats import PythonExpression
from refinery.lib.meta import metavars
from refinery.lib.tools import isbuffer
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class dedup(Unit):
    """
    Deduplicates a sequence of multiple inputs. The deduplication is limited to the current `refinery.lib.frame`.
    """
    def __init__(
        self,
        key: Param[str, Arg.String('key', help='An optional meta variable expression to deduplicate.')] = None,
        count: Param[bool, Arg.Switch('-c', help='Store the count of each deduplicated chunk.')] = False
    ):
        super().__init__(key=key, count=count)

    def filter(self, chunks):
        keyvar = self.args.key

        if keyvar is not None:
            def key(chunk):
                v = PythonExpression.Evaluate(keyvar, metavars(chunk))
                if isbuffer(v):
                    v = md5(v).digest()
                return v
        else:
            def key(chunk):
                return md5(chunk).digest()

        if self.args.count:
            counts = {}
            buffer = {}
            hashes = None
        else:
            hashes = set()
            counts = None
            buffer = None

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
