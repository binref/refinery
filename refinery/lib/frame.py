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

import itertools
import zlib
import uuid

from typing import Generator, Iterable, BinaryIO, Callable, Optional, List, Tuple, Dict, ByteString, Any
from typing import TYPE_CHECKING
from refinery.lib.structures import MemoryFile
from refinery.lib.meta import LazyMetaOracle

if TYPE_CHECKING:
    from msgpack.fallback import Unpacker

try:
    import msgpack
except ModuleNotFoundError:
    msgpack = None

__all__ = [
    'Chunk',
    'Framed',
    'FrameUnpacker',
    'MAGIC',
    'MSIZE',
    'generate_frame_header'
]


MAGIC = bytes.fromhex('FEED1985C0CAC01AC0DE')
"""
This is the magic signature that is used by refinery to prefix serialized frame data. If a unit
reads data from STDIN that is prefixed with these bytes, it assumes that serialized frame data
follows. Otherwise, the input is treated as a single unframed chunk.
"""
MSIZE = len(MAGIC) + 1
"""
This is the length of the data returned by `refinery.lib.frame.generate_frame_header`.
"""


def generate_frame_header(scope: int):
    """
    This function generates a frame header for a frame tree of depth equal to `scope`. The depth
    is encoded as a single byte following `refinery.lib.frame.MAGIC`. This implies a depth limit
    of 255 for frame trees in refinery, and I dearly hope that noone is insane enough to build a
    refinery pipeline that would be affected.
    """
    if scope > 0xFF:
        raise ValueError('Maximum frame depth exceeded.')
    return B'%s%c' % (MAGIC, scope)


class Chunk(bytearray):
    """
    Represents the individual chunks in a frame. The `refinery.units.Unit.filter` method receives
    an iterable of `refinery.lib.frame.Chunk`s.
    """
    temp: Any
    """
    Units can use this field to transport temporary data between different callbacks. For example,
    a unit might want to transport information from `refinery.units.Unit.filter` to:

    - `refinery.units.Unit.reverse`
    - `refinery.units.Unit.process`

    These methods, in turn, might want to transport information to `refinery.units.Unit.finish`.
    """
    uuid: uuid.UUID
    """
    Each chunk object carries a unique identifier. The `refinery.units.DelayedArgumentProxy` uses
    this property to check whether `refinery.units.Unit` command-line arguments were previously
    evaluated against this chunk. Otherwise `refinery.lib.argformats.DelayedArgument`s that alter
    the input data could produce unexpected results when the argument proxy is mapped against the
    same chunk twice.
    """

    __slots__ = (
        '_meta',
        '_view',
        '_path',
        '_fill_scope',
        '_fill_batch',
        'temp',
        'uuid',
    )

    def __init__(
        self,
        data: Optional[ByteString] = None,
        path: Optional[List[int]] = None,
        view: Optional[List[bool]] = None,
        meta: Optional[Dict[str, Any]] = None,
        seed: Optional[Dict[str, list]] = None,
        fill_scope: Optional[bool] = None,
        fill_batch: Optional[int] = None,
        ignore_chunk_properties: bool = False,
    ):
        if data is None:
            bytearray.__init__(self)
        else:
            bytearray.__init__(self, data)

        self.uuid = uuid.uuid4()
        self.temp = None

        if path is None:
            path = []
        if view is None:
            view = [False] * len(path)
        elif len(view) != len(path):
            raise ValueError('view must have the same length as path')

        if not ignore_chunk_properties and isinstance(data, Chunk):
            path = path or list(data.path)
            view = view or list(data.view)
            meta = meta or data.meta
            fill_scope = fill_scope or data._fill_scope
            fill_batch = fill_batch or data._fill_batch

        self._view: List[bool] = view
        self._path: List[int] = path
        self._fill_scope: Optional[bool] = fill_scope
        self._fill_batch: Optional[bool] = fill_batch

        self._meta = m = LazyMetaOracle(self, scope=self.scope, seed=seed)
        if meta is not None:
            m.update(meta)

    @classmethod
    def Wrap(cls, data):
        if isinstance(data, cls):
            return data
        return cls(data)

    def set_next_scope(self, visible: bool) -> None:
        self._fill_scope = visible

    def set_next_batch(self, batch: int) -> None:
        """
        This function allows units to emit trees of depth one rather than lists. When a unit emits
        a chunk at index `a`, sets the next batch to `b`, and when a double frame opens after this
        unit's invocation, then said chunk will have `a/b` added to its path. By default, `b` would
        always be `0`. For example, the `refinery.rex` unit uses this feature. As a result:

            $ emit #1yellow-#3red-#2orange | rex #(.)([a-z]+) {1} {2} [[| pop x:e ]| rep v:x ]]
            yellow
            red
            red
            red
            orange
            orange

        The double frame after `refinery.rex` looks like this:

            [[1,yellow],[2,red],[3,orange]]

        By default, the frame would simply look like this:

            [[1,yellow,2,red,3,orange]]

        This feature is useful for `refinery.units.Unit`s that produce multiple outputs for each of
        a number of intermediate results - in the case of `refinery.rex`, that intermediate result
        is a regular expression match, and `refinery.rex` allows to produce different outputs for
        each of those.
        """
        self._fill_batch = batch

    @property
    def scope(self) -> int:
        """
        This value is the length of `refinery.lib.frame.Chunk.path` and therefore corresponds to
        the depth of the frame tree. It is called "scope" because it is equally the scope at which
        new metadata variables for this chunk will be created.
        """
        return len(self._path)

    @property
    def view(self) -> List[bool]:
        """
        This tuple of boolean values indicates the visibility of this chunk at each layer of
        the frame tree. The `refinery.scope` unit can be used to change visibility of chunks
        within a frame.
        """
        return self._view

    @property
    def path(self) -> List[int]:
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
        Every chunk can contain a dictionary of arbitrary metadata. Further details about this data
        are available in the module-level documetnation of `refinery.lib.meta`.
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
        view = self._view
        if not view:
            if not value:
                raise AttributeError('cannot make chunk invisible outside frame')
        else:
            view[~0] = value

    @classmethod
    def unpack(cls, stream):
        """
        Classmethod to read a serialized chunk from an unpacker stream.
        """
        item = next(stream)
        path, view, meta, fs, data = item
        return cls(data, path=path, view=view, seed=meta, fill_scope=fs)

    def pack(self, nest: int = 0, position: int = 0, serialize: bool = True):
        """
        This function is equivalent to `refinery.lib.frame.Chunk.pack` if `serialize` is `True`.
        Otherwise, the function creates a copy of the chunk whose location in the frame tree has
        been adjusted based on the given nesting and position. With the default arguments, the
        value of all the following expressions is the same:

        - `chunk.pack(nesting, position)`
        - `chunk.gift(nesting, position, True)`
        - `chunk.gift(nesting, position).pack()`

        The difference, however, is that the first two options require one less copy operation
        than the latter.
        """
        scope = self.scope + nest
        fs = self._fill_scope
        fb = self._fill_batch
        if nest > 0:
            view = list(self._view)
            path = list(self._path)
            if nest > 0:
                if fs is not None:
                    view.extend(itertools.repeat(self.visible, nest - 1))
                    view.append(fs)
                    fs = None
                else:
                    view.extend(itertools.repeat(self.visible, nest))
                if fb is not None and nest > 1:
                    path.append(position)
                    path.append(fb)
                    path.extend(itertools.repeat(0, nest - 2))
                else:
                    path.append(position)
                    path.extend(itertools.repeat(0, nest - 1))
        elif nest < 0:
            view = self._view[:nest]
            path = self._path[:nest]
        else:
            view = self._view
            path = self._path
            if not serialize:
                view = list(view)
                path = list(path)

        assert len(path) == scope
        assert len(view) == scope

        meta = self._meta.serialize(self.scope + nest)

        if serialize:
            item = (path, view, meta, fs, self)
            return msgpack.packb(item)
        else:
            return Chunk(self, path, view, None, meta, fs, fb,
                ignore_chunk_properties=True)

    def __repr__(self) -> str:
        layer = '/'.join(str(p) if s else F'!{p}' for p, s in zip(self._path, self._view))
        layer = layer and '/' + layer
        return F'<chunk{layer}:{bytes(self)!r}>'

    def intersect(self, other: Chunk):
        """
        Removes all meta variables from this chunk whose value differs from those of the `other`
        inut chunk.
        """
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

    def truncate(self, scope: int = 0):
        """
        Truncate the `refinery.lib.frame.Chunk.path` and `refinery.lib.frame.Chunk.view` lists
        to the given length, setting the `refinery.lib.frame.Chunk.scope` to the given value.
        """
        del self._path[scope:]
        del self._view[scope:]
        return self

    def copy(self, meta=True, data=True) -> Chunk:
        """
        Produce a copy of this chunk. The metadata is copied if the `meta` argument is `True`,
        otherwise the copy has no metadata. The body of the chunk is copied only if the `data`
        argument is `True`.
        """
        data = data and self or None
        copy = Chunk(
            data,
            path=list(self._path),
            view=list(self._view),
            fill_scope=self._fill_scope,
            fill_batch=self._fill_batch,
            ignore_chunk_properties=True,
        )
        if meta:
            copy.meta.update(self.meta)
        if copy.meta.scope != copy.scope:
            raise RuntimeError
        return copy

    def __copy__(self):
        return self.copy()

    def __deepcopy__(self, memo):
        raise NotImplementedError


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
    depth: int
    trunk: Tuple[int, ...]
    check: Tuple[int, ...]
    stream: Optional[BinaryIO]
    finished: bool
    framed: bool
    unpacker: Optional[Unpacker]

    def __init__(self, stream: Optional[BinaryIO]):
        self.finished = False
        self.trunk = ()
        self.check = ()
        self.stream = None
        self.depth = 0
        self.next_chunk = None
        buffer = stream and stream.read(len(MAGIC)) or None
        if buffer == MAGIC:
            self.depth, = stream.read(1)
            self.framed = True
            self.stream = stream
            self.unpacker = msgpack.Unpacker(max_buffer_size=0xFFFFFFFF, use_list=True)
            self._advance()
        else:
            self.unpacker = None
            self.framed = False
            self.depth = 0
            self.next_chunk = Chunk()
            while buffer:
                self.next_chunk.extend(buffer)
                buffer = stream.read()

    def _advance(self) -> bool:
        while not self.finished:
            try:
                self.next_chunk = chunk = Chunk.unpack(self.unpacker)
                self.check = tuple(chunk.path)
                if chunk.scope != self.depth:
                    raise RuntimeError(F'Frame of depth {self.depth} contained chunk of scope {chunk.scope}.')
                return True
            except StopIteration:
                pass
            try:
                recv = self.stream.read1()
            except TypeError:
                raise
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
        self.trunk = self.check
        return True

    def abort(self):
        """
        Abort unpacking chunks from the frame.
        """
        if self.depth > 1:
            while not self.finished and self.trunk == self.check:
                self._advance()
        else:
            self.unpacker = None
            self.finished = True

    @property
    def eol(self) -> bool:
        """
        Specifies whether the current frame was fully consumed.
        """
        return self.trunk != self.peek

    @property
    def peek(self) -> Tuple[int, ...]:
        """
        Contains the identifier of the next frame.
        """
        return self.check

    def __iter__(self) -> Generator[Chunk, None, None]:
        if self.finished:
            return
        if not self.framed:
            yield self.next_chunk
            self.finished = True
            return
        while not self.finished and self.trunk == self.check:
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
        serialized: bool = True,
    ):
        self.unpack = FrameUnpacker(stream)
        self.action = action
        self.filter = filter
        self.finish = finish
        self.serialized = serialized
        self.nesting = nesting
        self.squeeze = squeeze

    def _apply_filter(self) -> Iterable[Chunk]:

        def autoindex(it: Iterable[Chunk]):
            for k, chunk in enumerate(it):
                chunk.meta.index = k
                yield chunk

        chunks = iter(self.unpack)
        header = list(itertools.islice(chunks, 0, 2))
        if not header:
            return
        elif len(header) > 1:
            chunks = itertools.chain(header, chunks)
            chunks = autoindex(chunks)
        else:
            header[0].meta.index = 0
            chunks = iter(header)
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
        return self.nesting + self.unpack.depth < 1

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
        return self.nesting + self.unpack.depth < 0

    def _generate_chunks(self, parent: Chunk):
        path = list(parent.path)
        view = list(parent.view)
        meta = parent.meta
        scope = parent.scope

        def inherit(chunk: Chunk):
            if chunk is parent:
                return chunk
            if path:
                chunk._path[:] = path
            if view and not chunk._view:
                chunk._view[:] = view
            chunk._meta.inherit(meta)
            return chunk.truncate(scope)

        if not self.squeeze:
            for chunk in self.action(parent):
                yield inherit(chunk)
        else:
            it = self.action(parent)
            for header in it:
                buffer = MemoryFile(header)
                buffer.seek(len(header))
                break
            else:
                return
            for item in it:
                header.intersect(item)
                buffer.write(item)
            inherit(header)
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
        nesting = self.nesting
        serialized = self.serialized
        scope = max(self.unpack.depth + nesting, 0)
        if self.unpack.finished:
            if scope:
                yield generate_frame_header(scope)
            return
        if nesting > 0:
            assert scope
            yield generate_frame_header(scope)
            while self.unpack.nextframe():
                for k, chunk in enumerate(self._apply_filter()):
                    if not chunk.visible:
                        yield chunk.pack(nesting, k, serialized)
                        continue
                    for result in self._generate_chunks(chunk):
                        yield result.pack(nesting, k, serialized)
        elif not self.unpack.framed:
            for chunk in self._apply_filter():
                yield from self._generate_bytes(chunk)
        elif nesting == 0:
            assert scope
            yield generate_frame_header(scope)
            while self.unpack.nextframe():
                for chunk in self._apply_filter():
                    if not chunk.visible:
                        yield chunk.pack(0, 0, serialized)
                        continue
                    for result in self._generate_chunks(chunk):
                        yield result.pack(0, 0, serialized)
        else:
            trunk = None
            check = scope + 1
            if scope:
                yield generate_frame_header(scope)
            while self.unpack.nextframe():
                for chunk in self._apply_filter():
                    results = self._generate_chunks(chunk) if chunk.visible else (chunk,)
                    if not scope:
                        for chunk in results:
                            yield chunk.truncate()
                        continue
                    for result in results:
                        if trunk is None:
                            trunk = result
                        elif result.path[:check] == trunk.path[:check]:
                            trunk.intersect(result)
                            trunk.extend(result)
                        else:
                            yield trunk.pack(nesting, 0, serialized)
                            trunk = result
                if not scope or trunk is None:
                    continue
            if trunk is not None:
                yield trunk.pack(nesting, 0, serialized)
