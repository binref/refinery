#!/usr/bin/env python3
# -*- coding: utf-8 -*-
R"""
Some refinery units produce more than one output when applied to an input. For example,
`refinery.chop` will chop the input data into evenly sized blocks and emit each of them
as a single output. By default, if no framing syntax is used, multiple outputs are
separated by line breaks, which is often desirable when text data is extracted. However,
for processing binary data, this is equally often more than useless. To process the list
of results generated by any refinery unit, end the command for this unit with the
special argument `[`. This argument has to be the last argument to be recognized as a
framing initialization. If this syntax is used, the list of results is emitted in an
internal format which allows arbitrarily nested lists of binary chunks to be processed.

### Simple Frame Example

    $ emit OOOOOOOO | chop 2 [| ccp F | cca . ]
    FOO.FOO.FOO.FOO.

Here, the string `OOOOOOOO` is first chopped into blocks of 2, yielding the **frame**
`[OO, OO, OO, OO]` which is then forwarded to the next command. If a `refinery.units.Unit`
receives input in framed format, each chunk of the frame is processed individually and
emitted as one output chunk. In this case, `refinery.ccp` simply prepends `F` to every
input, producing the frame `[FOO, FOO, FOO, FOO]`. Finally, `refinery.cca` appends a period
to each chunk. When a unit is given the closing bracket as the last argument, this
concludes processing of one frame which results in concatenation of all binary chunks in
the frame.

### Frame Layers

Frames can be nested arbitrarily, and `refinery.sep` can be used to insert a separator
(the default is line break) between all chunks in the frame:

    $ emit OOOOOOOO | chop 4 [| chop 2 [| ccp F | cca . ]| sep ]
    FOO.FOO.
    FOO.FOO.

Here, we first produce the two-layered **frame tree** `[[OO,OO], [OO,OO]]` by using two
`refinery.chop` invocations. We refer to this data as a tree because, well, it is one:

    LAYER 1:      [[..],[..]]
                    /     \
    LAYER 2:    [OO,OO] [OO,OO]

The bottom layer is processed as before, yielding `[FOO.FOO., FOO.FOO.]`. Next, the unit
`refinery.sep` inserts a line break character between the two chunks in this frame.

### Adding Line Breaks Easily

Since separating data with line breaks is a common requirement, it is also possible to use
one more closing bracket than necessary at the end of a frame to separate all chunks by line
breaks:

    $ emit OOOOOOOO | chop 4 [| chop 2 [| ccp F | cca . ]]]
    FOO.FOO.
    FOO.FOO.

### Squeezing

Inside a frame, application of a `refinery.units.Unit` with multiple outputs will substitute the
input by the corresponding list of outputs. For example,

    $ emit OOOOOOOO | chop 4 [| chop 2 | ccp F ]]

has the exact same output as the following command:

    $ emit 00000000 | chop 2 [| ccp F ]]

In the first case, we create the frame `[OOOO, OOOO]` and then apply `chop 2` to each chunk,
which results in the frame `[OO, OO, OO, OO]`. Now, consider the example

    $ emit OOCLOOCL | chop 4 [| snip 2::-1 3: ]]
    COO
    L
    COO
    L

With what we have learned so far, if we wanted it to spell `COOL` twice instead,we would have
to use the following and slightly awkward syntax:

    $ emit OOCLOOCL | chop 4 [| snip 2::-1 3 [| nop ]| sep ]
    COOL
    COOL

This is because the `snip` command, by default, will simply insert the list `[COO, L]` into
the complete frame, creating the output sequence `[COO, L, COO, L]` and all of these chunks
will be separated by line breaks. For this reason, the squeeze syntax exists. If the brackets
at the end of a refinery command are prefixed by the sequence `[]`, i.e. an opening bracket
followed directly by a closing one, then all outputs of the unit are fused into a single
output chunk by concatenating them. In our example:

    $ emit OOCLOOCL | chop 4 [| snip 2::-1 3 []]]
    COOL
    COOL


### Scoping

It is possible to alter the **visibility** of `refinery.lib.frame.Chunk`, primarily by
using `refinery.scope`. The unit accepts a slice argument which defines the indices of
the current frame that remain visible. All subsequent units will only process visible
chunks and simply forward the ones that are not visible. `refinery.lib.frame.Chunk`s
remain invisible when a new frame layer opens:

    $ emit BINARY REFINERY [| scope 0 | clower | sep - ]
    binary-REFINERY

Here, the scope was limited to the first chunk `BINARY` which was transformed to lower
case, but the second chunk `REFINERY` was left untouched. A somewhat more complex example:

    $ emit aaaaaaaa namtaB [| scope 0 | rex . [| ccp N ]| scope 1 | rev | sep - ]
    NaNaNaNaNaNaNaNa-Batman

Note that `refinery.sep` makes all chunks in the frame visible by default, because it is
intended to sit at the end of a frame. Otherwise, `NaNaNaNaNaNaNaNa` and `Batman` in the
above example would not be separated by a dash.
"""
from __future__ import annotations

import copy
import json
import base64
import itertools
import zlib

from typing import Generator, Iterable, BinaryIO, Callable, Optional, Tuple, Dict, ByteString, Any
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import isbuffer
from refinery.lib.meta import LazyMetaOracle

try:
    import msgpack
except ModuleNotFoundError:
    msgpack = None

__all__ = [
    'Chunk',
    'Framed',
    'FrameUnpacker'
]


class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isbuffer(obj):
            return {'_bin': base64.b85encode(obj).decode('ascii')}
        return super().default(obj)


class BytesDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if isinstance(obj, dict) and len(obj) == 1 and '_bin' in obj:
            return base64.b85decode(obj['_bin'])
        return obj


MAGIC = bytes.fromhex('FEED1985C0CAC01AC0DE')


def generate_frame_header(gauge: int):
    if gauge > 0xFE:
        raise ValueError('Maximum frame depth exceeded.')
    return B'%s%c' % (MAGIC, gauge)


class Chunk(bytearray):
    """
    Represents the individual chunks in a frame. The `refinery.units.Unit.filter` method
    receives an iterable of `refinery.lib.frame.Chunk`s.
    """
    temp: Any = None
    meta: LazyMetaOracle

    def __init__(
        self,
        data: Optional[ByteString] = None,
        path: Tuple[int] = (),
        view: Optional[Tuple[bool]] = None,
        meta: Optional[Dict[str, Any]] = None,
        fill: Optional[bool] = None
    ):
        if data is None:
            bytearray.__init__(self)
        else:
            bytearray.__init__(self, data)

        view = view or (False,) * len(path)
        if len(view) != len(path):
            raise ValueError('skipping must have the same length as path')

        if isinstance(data, Chunk):
            path = path or data.path
            view = view or data.view
            meta = meta or data.meta
            fill = fill or data.fill

        self._view: Tuple[bool] = view
        self._path: Tuple[int] = path
        self._fill: Optional[bool] = fill

        self._meta = m = LazyMetaOracle(self)
        if meta is not None:
            m.update(meta)

    @property
    def guid(self) -> int:
        return hash((id(self), *(id(v) for v in self.meta.values())))

    @property
    def fill(self) -> bool:
        return self._fill

    def set_next_scope(self, visible: bool) -> None:
        self._fill = visible

    def truncate(self, gauge):
        self._path = self._path[:gauge]
        self._view = self._view[:gauge]

    def nest(self, *ids):
        """
        Nest this chunk deeper by providing a sequence of indices inside each new layer of the
        frame. The `refinery.lib.frame.Chunk.path` tuple is extended by these values. The
        visibility of the `refinery.lib.frame.Chunk` at each new layer is inherited from its
        current visibility.
        """
        if self._fill is not None:
            self._view += (self.visible,) * (len(ids) - 1) + (self._fill,)
            self._fill = None
        else:
            self._view += (self.visible,) * len(ids)
        self._path += ids
        return self

    @property
    def view(self) -> Tuple[bool]:
        """
        This tuple of boolean values indicates the visibility of this chunk at each layer of
        the frame tree. The `refinery.scope` unit can be used to change visibility of chunks
        within a frame.
        """
        return self._view

    @property
    def path(self) -> Tuple[int]:
        """
        The vertices in each frame tree layer are sequentially numbered by their order of
        appearance in the stream. The `refinery.lib.frame.Chunk.path` contains the numbers of
        the vertices (in each layer) which define the path from the root of the frame tree
        to the leaf vertex representing this `refinery.lib.frame.Chunk`
        """
        return self._path

    @property
    def meta(self) -> LazyMetaOracle:
        """
        Every chunk can contain a dictionary of arbitrary metadata.
        """
        if self._meta.chunk is not self:
            raise RuntimeError('meta dictionary carries invalid parent reference')
        return self._meta

    @property
    def visible(self):
        """
        This property defines whether the chunk is currently visible. It defaults to true if the
        chunk is not part of a frame and is otherwise the same as the last element of the tuple
        `refinery.lib.frame.Chunk.view`. Setting this property will correspondingly alter the last
        entry of `refinery.lib.frame.Chunk.view`.
        Setting this property on an unframed `refinery.lib.frame.Chunk` raises an `AttributeError`.
        """
        return not self._view or self._view[~0]

    @property
    def scopable(self):
        """
        This property defines whether the chunk can be made visible in the current frame.
        """
        return len(self._view) <= 1 or self._view[~1]

    @visible.setter
    def visible(self, value: bool):
        if not value and not self._view:
            raise AttributeError('cannot make chunk invisible outside frame')
        if value != self.visible:
            self._view = self._view[:~0] + (value,)

    def inherit(self, parent: Chunk):
        """
        This method can be used to take over properties of a parent `refinery.lib.frame.Chunk`.
        """
        self._path = parent._path
        self._view = self._view or parent._view
        meta = self._meta
        for key, value in parent.meta.items():
            if key in meta:
                continue
            try:
                costly = self._meta.DERIVATION_MAP[key].costly
            except KeyError:
                recompute = costly = False
            else:
                recompute = True
            if recompute:
                if costly and len(self) >= 0x1000 and hash(self) != hash(parent):
                    # discard meta-variables that would be too costly to recompute
                    continue
                value = meta[key]
            meta[key] = value
        return self

    @classmethod
    def unpack(cls, stream):
        """
        Classmethod to read a serialized chunk from an unpacker stream.
        """
        item = next(stream)
        path, view, meta, fill, data = item
        return cls(data, path, view=view, meta=meta, fill=fill)

    def pack(self):
        """
        Return the serialized representation of this chunk.
        """
        obj = (self._path, self._view, self._meta.serializable(), self._fill, self)
        return msgpack.packb(obj)

    def __repr__(self) -> str:
        layer = '/'.join('#' if not s else str(p) for p, s in zip(self._path, self._view))
        layer = layer and '/' + layer
        metas = ','.join(self._meta)
        metas = metas and F' meta=({metas})'
        return F'<chunk{layer}{metas} size={len(self)} data={repr(bytes(self))}>'

    def __iand__(self, other: Chunk):
        other_meta = other._meta
        meta = self._meta
        for key, value in list(meta.items()):
            if other_meta.get(key) != value:
                meta.discard(key)
        return self

    def __str__(self):
        try:
            return self.decode('UTF8')
        except UnicodeDecodeError:
            return self.hex()

    def __hash__(self):
        return hash(zlib.adler32(self))

    def __getitem__(self, bounds):
        if isinstance(bounds, str):
            return self._meta[bounds]
        return bytearray.__getitem__(self, bounds)

    def __setitem__(self, bounds, value):
        if isinstance(bounds, str):
            self._meta[bounds] = value
        else:
            bytearray.__setitem__(self, bounds, value)

    def copy(self) -> Chunk:
        return self.__copy__()

    def __copy__(self):
        return Chunk(self, self._path, self._view, self._meta, self._fill)

    def __deepcopy__(self, memo):
        dc = Chunk(self, self._path, self._view, self._fill)
        memo[id(self)] = dc
        memo[id(self._meta)] = dc.meta
        for key, value in self._meta.items():
            dc.meta[key] = copy.deepcopy(value, memo)
        return dc


class FrameUnpacker(Iterable[Chunk]):
    """
    Provides a unified interface to read both framed and raw input data from a stream. After
    loading a framed input stream, the object provides an iterator over the first **frame** in
    the bottom **layer** of the frame tree. Consider this doubly layered frame tree:

        [[FOO, BAR], [BOO, BAZ]]

    The `refinery.lib.frame.FrameUnpacker` object will first be an iterator over the first frame
    `[FOO, BAR]`. After consuming this iterator, the `refinery.lib.frame.FrameUnpacker.nextframe`
    method can be called to load the next frame, at which point the object will become an
    iterator over `[BOO, BAZ]`.
    """
    next_chunk: Optional[Chunk]
    gauge: int
    trunk: Tuple[int, ...]
    stream: Optional[BinaryIO]
    finished: bool
    framed: bool
    unpacker: Optional[msgpack.Unpacker]

    def __init__(self, stream: Optional[BinaryIO]):
        self.finished = False
        self.trunk = ()
        self.stream = None
        self.gauge = 0
        self.next_chunk = None
        buffer = stream and stream.read(len(MAGIC)) or None
        if buffer == MAGIC:
            self.gauge, = stream.read(1)
            self.framed = True
            self.stream = stream
            self.unpacker = msgpack.Unpacker(max_buffer_size=0xFFFFFFFF, use_list=False)
            self._advance()
        else:
            self.unpacker = None
            self.framed = False
            self.gauge = 0
            self.next_chunk = Chunk()
            while buffer:
                self.next_chunk.extend(buffer)
                buffer = stream.read()

    def _advance(self) -> bool:
        while not self.finished:
            try:
                self.next_chunk = chunk = Chunk.unpack(self.unpacker)
                if len(chunk.path) != self.gauge:
                    raise RuntimeError(F'Frame with gauge {self.gauge} contained chunk of depth {len(chunk.path)}.')
                return True
            except StopIteration:
                pass
            try:
                recv = self.stream.read1()
            except TypeError:
                recv = None
            recv = recv or self.stream.read()
            if not recv:
                break
            self.unpacker.feed(recv)
        self.finished = True
        return False

    def nextframe(self) -> bool:
        """
        Once the iterator is consumed, calling this function will return `True` if
        and only if another frame with input data has been loaded, in which case
        the object will provide an iterator over the freshly loaded frame. If this
        function returns `False`, all input data has been consumed.
        """
        if self.finished:
            return False
        self.trunk = self.next_chunk.path
        return True

    def abort(self):
        if self.gauge > 1:
            while not self.finished and self.trunk == self.next_chunk.path:
                self._advance()
        else:
            self.unpacker = None
            self.finished = True

    @property
    def eol(self) -> bool:
        return self.trunk != self.peek

    @property
    def peek(self) -> Tuple[int]:
        """
        Contains the identifier of the next frame.
        """
        return self.next_chunk.path

    def __iter__(self) -> Generator[Chunk, None, None]:
        if self.finished:
            return
        if not self.framed:
            yield self.next_chunk
            self.finished = True
            return
        while not self.finished and self.trunk == self.next_chunk.path:
            yield self.next_chunk
            self._advance()


class Framed:
    """
    A proxy interface to ingest and output framed data. It is given an `action` to be
    performed for each elementary chunk of data, a `stream` of input data, and an integer
    argument `nested` which specifies the relative amount of nesting to be performed
    by the interface. This parameter should either be `1` if the interface should output
    the results at an additional layer, `0` if the nesting depth of the data should
    remain unchanged, and a negative amount if frame layers are to be collapsed. After
    initialization, the `refinery.lib.frame.Framed` object is an iterator that yields
    bytestrings which can be forwarded as the output of the operation with all framing
    already taken care of.
    """
    def __init__(
        self,
        action : Callable[[bytearray], Iterable[Chunk]],
        stream : BinaryIO,
        nesting: int = 0,
        squeeze: bool = False,
        filter : Optional[Callable[[Iterable[Chunk]], Iterable[Chunk]]] = None,
        finish : Optional[Callable[[], Iterable[Chunk]]] = None,
    ):
        self.unpack = FrameUnpacker(stream)
        self.action = action
        self.filter = filter
        self.finish = finish
        self.nesting = nesting
        self.squeeze = squeeze

    def _apply_filter(self) -> Iterable[Chunk]:

        def autoindex(it: Iterable[Chunk]):
            for k, chunk in enumerate(it):
                chunk.meta.update_index(k)
                yield chunk

        chunks = iter(self.unpack)
        header = list(itertools.islice(chunks, 0, 2))
        if header:
            chunks = itertools.chain(header, chunks)
            if len(header) > 1:
                chunks = autoindex(chunks)
            if header[0].scopable:
                chunks = self.filter(chunks)
            yield from chunks

        if not self.unpack.eol:  # filter did not consume the iterable
            self.unpack.abort()

        if self.unpack.finished and self.finish:
            yield from self.finish()

    @property
    def unframed(self) -> bool:
        """
        This property is true if the output data is not framed.
        """
        return self.nesting + self.unpack.gauge < 1

    @property
    def framebreak(self) -> bool:
        """
        This property will be true if the data generated by this framing interface should
        be separated by linebreaks. This happens when one of the following is true:
        - The requested nesting was smaller than required to close all existing frames.
        - The input data was not framed and the nesting did not increase in this unit
        """
        if not self.unpack.framed:
            return self.nesting < 1
        return self.nesting + self.unpack.gauge < 0

    def _generate_chunks(self, parent: Chunk):
        if not self.squeeze:
            for item in self.action(parent):
                yield copy.copy(item).inherit(parent)
            return
        it = self.action(parent)
        try:
            header = next(it)
        except StopIteration:
            return
        else:
            header.inherit(parent)
            buffer = MemoryFile(header)
            buffer.seek(len(header))
        for item in it:
            header &= item
            buffer.write(item)
        yield header

    def _generate_bytes(self, data: ByteString):
        if not self.squeeze:
            yield from self.action(data)
            return
        buffer = MemoryFile(bytearray())
        for item in self.action(data):
            buffer.write(item)
        yield buffer.getbuffer()

    def __iter__(self):
        gauge = max(self.unpack.gauge + self.nesting, 0)
        if self.unpack.finished:
            if gauge:
                yield generate_frame_header(gauge)
            return
        if self.nesting > 0:
            assert gauge
            yield generate_frame_header(gauge)
            rest = (0,) * (self.nesting - 1)
            while self.unpack.nextframe():
                for k, chunk in enumerate(self._apply_filter()):
                    if not chunk.visible:
                        yield chunk.nest(k, *rest).pack()
                        continue
                    for result in self._generate_chunks(chunk):
                        yield result.nest(k, *rest).pack()
        elif not self.unpack.framed:
            for chunk in self._apply_filter():
                yield from self._generate_bytes(chunk)
        elif self.nesting == 0:
            assert gauge
            yield generate_frame_header(gauge)
            while self.unpack.nextframe():
                for chunk in self._apply_filter():
                    if not chunk.visible:
                        yield chunk.pack()
                        continue
                    for result in self._generate_chunks(chunk):
                        yield result.pack()
        else:
            trunk = None
            if gauge:
                yield generate_frame_header(gauge)
            while self.unpack.nextframe():
                for chunk in self._apply_filter():
                    results = self._generate_chunks(chunk) if chunk.visible else (chunk,)
                    if not gauge:
                        yield from results
                        continue
                    for result in results:
                        if trunk is None:
                            trunk = result
                        elif result.path[gauge:] == trunk.path[gauge:]:
                            trunk &= result
                            trunk.extend(result)
                        else:
                            trunk.truncate(gauge)
                            yield trunk.pack()
                            trunk = result
                if not gauge or trunk is None:
                    continue
            if trunk is not None:
                trunk.truncate(gauge)
                yield trunk.pack()
