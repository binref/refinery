#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.lib.xml import XMLNodeBase
from refinery.lib.meta import metavars
from refinery.units.formats import XMLToPathExtractorUnit, UnpackResult, Arg

from io import StringIO
from html.parser import HTMLParser

_HTML_DATA_ROOT_TAG = 'html'


class HTMLNode(XMLNodeBase):
    __slots__ = 'indent',
    indent: str

    @property
    def textual(self) -> bool:
        return self.tag is None

    @property
    def root(self) -> bool:
        return self.tag == _HTML_DATA_ROOT_TAG

    def recover(self, inner=True) -> str:
        with StringIO() as stream:
            if not inner:
                stream.write(self.content)
            for child in self.children:
                child: HTMLNode
                stream.write(child.recover(False))
            if not inner and self.tag and not self.empty:
                stream.write(F'</{self.tag}>')
            return stream.getvalue()


class HTMLTreeParser(HTMLParser):

    _SELF_CLOSING_TAGS = {
        'area',
        'base',
        'br',
        'col',
        'embed',
        'hr',
        'img',
        'input',
        'link',
        'meta',
        'param',
        'source',
        'track',
        'wb',
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.root = self.tos = HTMLNode(_HTML_DATA_ROOT_TAG)

    def parse_starttag(self, i):
        end = super().parse_starttag(i)
        tag, eq, method = self.lasttag.partition('=')
        if eq != '=':
            return end
        if tag == 'macro' or tag == 'func' and 'exec' in method:
            self.lasttag = tag
            self.set_cdata_mode(tag)
            return end
        else:
            return end

    def handle_starttag(self, tag: str, attributes):
        tag, _, _ = tag.partition('=')
        if tag in self._SELF_CLOSING_TAGS:
            return
        node = HTMLNode(tag, None, self.tos, self.get_starttag_text(), attributes={
            key: value for key, value in attributes if key and value})
        children = self.tos.children
        previous = children[-1] if children else None
        self.tos = node
        children.append(node)
        if not previous or previous.tag is not None:
            return
        if self.getpos() == (1, len(previous.content)):
            node.content = previous.content + node.content
            previous.content = ''
            return
        lf = previous.content.rfind('\n') + 1
        if lf <= 0:
            return
        leading_space = previous.content[lf:]
        if not leading_space.isspace():
            return
        node.content = leading_space + node.content
        previous.content = previous.content[:lf]

    def handle_entityref(self, name: str) -> None:
        ntt = F'&{name};'
        if self.tos.children:
            last = self.tos.children[-1]
            if last.textual:
                last.content += ntt
                return
        self.tos.children.append(HTMLNode(None, None, self.tos, ntt))

    def handle_charref(self, name: str) -> None:
        self.handle_entityref(F'#{name}')

    def handle_startendtag(self, tag: str, attributes) -> None:
        self.handle_starttag(tag, attributes)
        self.tos.empty = True
        self.tos = self.tos.parent

    def handle_endtag(self, tag: str):
        cursor = self.tos
        while cursor.parent and cursor.tag != tag:
            xthtml.log_info(F'skipping unclosed tag: {cursor.tag}')
            cursor = cursor.parent
        if not cursor.parent:
            xthtml.log_warn(F'ignoring closing tag that never opened: {tag}')
            return
        self.tos = cursor.parent

    def handle_data(self, data):
        self.tos.children.append(HTMLNode(None, None, self.tos, data))


class xthtml(XMLToPathExtractorUnit):
    """
    The unit processes an HTML document and extracts the contents of all elemnts in the DOM of the
    given tag. The main purpose is to extract scripts from HTML documents.
    """
    def __init__(
        self, *paths,
        outer: Arg.Switch('-o', help='Include the HTML tags for an extracted element.') = False,
        attributes: Arg.Switch('-a', help='Populate chunk metadata with HTML tag attributes.') = False,
        list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        path=b'path'
    ):
        super().__init__(
            *paths,
            outer=outer,
            attributes=attributes,
            format='{tag}',
            path=path,
            list=list,
            join_path=join_path,
            drop_path=drop_path,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
        )

    def unpack(self, data):
        try:
            text = data.decode(self.codec)
        except UnicodeDecodeError:
            text = data.decode('latin1')

        html = HTMLTreeParser()
        html.feed(text)
        root = html.tos
        root.reindex()

        meta = metavars(data)
        path = self._make_path_builder(meta, root)

        while root.parent:
            self.log_info(F'tag was not closed: {root.tag}')
            root = root.parent

        while len(root.children) == 1:
            child, = root.children
            if child.tag != root.tag:
                break
            root = child

        def tree(root: HTMLNode, *parts: str):

            def outer(root: HTMLNode = root):
                return root.recover(inner=False).encode(self.codec)

            def inner(root: HTMLNode = root):
                return root.recover().encode(self.codec)

            tagpath = '/'.join(parts)
            meta = {}

            if self.args.attributes:
                meta.update(root.attributes)

            if root.root:
                yield UnpackResult(tagpath, inner, **meta)
            elif self.args.outer:
                yield UnpackResult(tagpath, outer, **meta)
            else:
                yield UnpackResult(tagpath, inner, **meta)

            for child in root.children:
                if child.textual:
                    continue
                yield from tree(child, *parts, path(child))

        yield from tree(root, path(root))

    @classmethod
    def handles(self, data: bytearray):
        from refinery.lib import mime
        info = mime.get_cached_file_magic_info(data)
        if info.extension == 'html':
            return True
        if info.mime.endswith('html'):
            return True
        return False
