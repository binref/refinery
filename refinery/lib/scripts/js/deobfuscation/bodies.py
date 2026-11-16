"""
Hold the one statement standing as the whole body of a branch or loop in the block the printer
writes for it.

The synthesizer writes every such body as a block (`JsSynthesizer._emit_statement_body`), so a body
the tree holds as one bare statement reads back from the printed file as a block around it. The
passes that sweep statements read the lists blocks hold, so a statement standing bare in a body
position is invisible to every one of them until the file is read again: a dead declaration as the
body of a loop survives a run and goes in the next. Wrapping each bare body where it stands keeps
the tree in the shape its own output reads back in, which is what makes one run settle what the
next would change. The body of a label stays bare, the one position the printer writes without a
block, and so does a body the parser could not read, whose unread text a block around it could cut.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, set_child, set_child_list
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsDoWhileStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsIfStatement,
    JsWhileStatement,
    JsWithStatement,
)

_WHOLE_BODY_SLOTS: tuple[tuple[type[Node], str], ...] = (
    (JsIfStatement, 'consequent'),
    (JsIfStatement, 'alternate'),
    (JsForStatement, 'body'),
    (JsForInStatement, 'body'),
    (JsForOfStatement, 'body'),
    (JsWhileStatement, 'body'),
    (JsDoWhileStatement, 'body'),
    (JsWithStatement, 'body'),
)


def _holds_unparsed_text(node: Node) -> bool:
    """
    Whether *node* is, or holds, text the parser could not read, which the printer writes as it
    stood: a brace put around it could open or close inside that text.
    """
    return bool(node.unparsed) or any(_holds_unparsed_text(child) for child in node.children())


class JsBareBodyBlocking(Transformer):
    """
    Wrap each statement standing as the whole body of a branch, a loop or a `with` statement in the
    block the printer writes for it, where it is a member of the list the sweeps read.
    """

    self_converging = True

    def generic_visit(self, node: Node):
        super().generic_visit(node)
        for kind, slot in _WHOLE_BODY_SLOTS:
            if not isinstance(node, kind):
                continue
            body = getattr(node, slot)
            if (
                body is None
                or isinstance(body, JsBlockStatement)
                or _holds_unparsed_text(body)
            ):
                continue
            block = JsBlockStatement(offset=body.offset)
            set_child_list(block, 'body', [body])
            set_child(node, slot, block)
            self.mark_changed()
        return None
