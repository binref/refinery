#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.lib.xml import XMLNodeBase
from refinery.units.formats import PathExtractorUnit, UnpackResult

import collections
import io

from html.parser import HTMLParser

_HTML_DATA_ROOT_TAG = '.'


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
        with io.StringIO() as stream:
            if not inner:
                stream.write(self.content)
            for child in self.children:
                child: HTMLNode
                stream.write(child.recover(False))
            if not inner and self.tag and not self.empty:
                stream.write(F'</{self.tag}>')
            return stream.getvalue()


class HTMLTreeParser(HTMLParser):

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.root = self.tos = HTMLNode(_HTML_DATA_ROOT_TAG)

    def handle_starttag(self, tag: str, attributes):
        node = HTMLNode(tag, self.tos, self.get_starttag_text(), attributes={
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
        self.tos.children.append(HTMLNode(None, self.tos, ntt))

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
        self.tos.children.append(HTMLNode(None, self.tos, data))


class xthtml(PathExtractorUnit):
    """
    The unit processes an HTML document and extracts the contents of all elemnts in the DOM of the
    given tag. The main purpose is to extract scripts from HTML documents.
    """
    def unpack(self, data):
        def tree(root: HTMLNode, *path):

            def outer(root: HTMLNode = root):
                return root.recover(inner=False).encode(self.codec)

            def inner(root: HTMLNode = root):
                return root.recover().encode(self.codec)

            tagpath = '/'.join(path)

            if root.root:
                yield UnpackResult(tagpath, inner)
            else:
                yield UnpackResult(F'{tagpath}.outer', outer)
                yield UnpackResult(F'{tagpath}.inner', inner)

            tag_count = collections.defaultdict(int)
            tag_index = collections.defaultdict(int)
            for node in root.children:
                tag_count[node.tag] += 1
            for node in root.children:
                node: HTMLNode
                name: str = node.tag
                if node.textual:
                    continue
                if tag_count[node.tag] > 1:
                    tag_index[node.tag] = index = tag_index[node.tag] + 1
                    name = F'{name}({index})'
                yield from tree(node, *path, name)

        parser = HTMLTreeParser()
        parser.feed(data.decode(self.codec))
        root = parser.tos
        while root.parent:
            self.log_info(F'tag was not closed: {root.tag}')
            root = root.parent

        yield from tree(root, root.tag)
