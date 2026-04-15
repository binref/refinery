"""
NSIS control flow graph construction and structural analysis.

This module builds a control flow graph from NSIS bytecode instructions and applies
pattern-based structural analysis to recover high-level control flow constructs
(If/Else, While, Do/While, Switch) from the flat instruction stream.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from refinery.lib.nsis.decompiler import NSScriptWriter

from refinery.lib.nsis.archive import NSHeader, Op


class NodeType(enum.Enum):
    """
    Classification of IR nodes.
    """
    INSTRUCTION = 'instruction'
    BRANCH = 'branch'
    GOTO = 'goto'
    LABEL = 'label'
    RETURN = 'return'
    BLOCK = 'block'
    IF = 'if'
    WHILE = 'while'
    DO_WHILE = 'do_while'


@dataclass
class NSNode:
    """
    Base class for all IR nodes in the structured representation.
    """
    node_type: NodeType


@dataclass
class InstructionNode(NSNode):
    """
    A non-branching, non-return instruction.
    """
    address: int
    opcode: Op

    def __init__(self, address: int, opcode: Op):
        super().__init__(NodeType.INSTRUCTION)
        self.address = address
        self.opcode = opcode


@dataclass
class BranchNode(NSNode):
    """
    A conditional branch instruction. The branch targets are encoded in the instruction
    arguments; this node preserves the original instruction for condition rendering.
    """
    address: int
    opcode: Op

    def __init__(self, address: int, opcode: Op):
        super().__init__(NodeType.BRANCH)
        self.address = address
        self.opcode = opcode


@dataclass
class GotoNode(NSNode):
    """
    An unconditional jump (Nop with nonzero target).
    """
    address: int
    target: int

    def __init__(self, address: int, target: int):
        super().__init__(NodeType.GOTO)
        self.address = address
        self.target = target


@dataclass
class LabelNode(NSNode):
    """
    A label marker at a given address.
    """
    address: int

    def __init__(self, address: int):
        super().__init__(NodeType.LABEL)
        self.address = address


@dataclass
class ReturnNode(NSNode):
    """
    An EW_RET instruction.
    """
    address: int

    def __init__(self, address: int):
        super().__init__(NodeType.RETURN)
        self.address = address


@dataclass
class BlockNode(NSNode):
    """
    A sequential list of child nodes.
    """
    body: list[NSNode] = field(default_factory=list)

    def __init__(self, body: list[NSNode] | None = None):
        super().__init__(NodeType.BLOCK)
        self.body = body if body is not None else []


@dataclass
class IfNode(NSNode):
    """
    A structured If/Else construct recovered from the CFG.
    """
    condition: BranchNode
    then_body: BlockNode
    else_body: BlockNode | None = None
    negated: bool = False

    def __init__(
        self,
        condition: BranchNode,
        then_body: BlockNode,
        else_body: BlockNode | None = None,
        negated: bool = False,
    ):
        super().__init__(NodeType.IF)
        self.condition = condition
        self.then_body = then_body
        self.else_body = else_body
        self.negated = negated


@dataclass
class WhileNode(NSNode):
    """
    A structured While loop (test at top).
    """
    condition: BranchNode
    body: BlockNode
    negated: bool = False

    def __init__(
        self,
        condition: BranchNode,
        body: BlockNode,
        negated: bool = False,
    ):
        super().__init__(NodeType.WHILE)
        self.condition = condition
        self.body = body
        self.negated = negated


@dataclass
class DoWhileNode(NSNode):
    """
    A structured Do/While loop (test at bottom).
    """
    body: BlockNode
    condition: BranchNode
    negated: bool = False

    def __init__(
        self,
        body: BlockNode,
        condition: BranchNode,
        negated: bool = False,
    ):
        super().__init__(NodeType.DO_WHILE)
        self.body = body
        self.condition = condition
        self.negated = negated


_GOTO_MASKS: dict[Op, int] = {
    Op.Nop            : 1 << 0,
    Op.IfFileExists   : 3 << 1,
    Op.IfFlag         : 3 << 0,
    Op.MessageBox     : 5 << 3,
    Op.StrCmp         : 3 << 2,
    Op.IntCmp         : 7 << 2,
    Op.IsWindow       : 3 << 1,
}


class BranchKind(enum.Enum):
    """
    Classification of a basic block's terminating branch.
    """
    FALL = 'fall'
    JUMP = 'jump'
    CONDITIONAL = 'conditional'
    RETURN = 'return'


@dataclass
class BasicBlock:
    """
    A maximal sequence of instructions with single entry and (for non-branches) single exit.
    """
    start: int
    end: int
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    kind: BranchKind = BranchKind.FALL

    @property
    def size(self) -> int:
        return self.end - self.start


def _resolve_param(param: int) -> int | None:
    """
    Resolve a single NSIS jump parameter to an instruction address.
    NSIS encodes targets as target + 1 (0 = fall through, negative = variable-indirect).
    Returns the target address, or None for fall-through/indirect.
    """
    signed = param if param < 0x80000000 else param - 0x100000000
    if signed > 0:
        return param - 1
    return None


def _find_leaders(header: NSHeader, start: int, end: int) -> set[int]:
    """
    Identify basic block leaders (first instruction of each block) in a code range.
    A leader is:
    - The first instruction (start)
    - Any jump target
    - Any instruction immediately following a branch or return
    """
    leaders: set[int] = {start}
    for k in range(start, end):
        insn = header.instructions[k]
        opcode = header.opcode(insn)
        if opcode is Op.Ret:
            if k + 1 < end:
                leaders.add(k + 1)
            continue
        if opcode is Op.Call:
            continue
        mask = _GOTO_MASKS.get(opcode)
        if mask is None:
            continue
        if k + 1 < end:
            leaders.add(k + 1)
        for i in range(6):
            if not mask:
                break
            if mask & 1:
                target = _resolve_param(insn.arguments[i])
                if target is not None and start <= target < end:
                    leaders.add(target)
            mask >>= 1
    return leaders


def build_cfg(header: NSHeader, start: int, end: int) -> dict[int, BasicBlock]:
    """
    Build a control flow graph for the instruction range [start, end).

    Returns a mapping from block start address to BasicBlock. Each block covers
    a maximal run of instructions with no internal branches or join points.
    """
    leaders = _find_leaders(header, start, end)
    sorted_leaders = sorted(leaders)
    blocks: dict[int, BasicBlock] = {}
    for idx, leader in enumerate(sorted_leaders):
        block_end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else end
        blocks[leader] = BasicBlock(start=leader, end=block_end)

    for addr, block in blocks.items():
        if block.end <= block.start:
            continue
        last = block.end - 1
        insn = header.instructions[last]
        opcode = header.opcode(insn)

        if opcode is Op.Ret:
            block.kind = BranchKind.RETURN
            continue

        mask = _GOTO_MASKS.get(opcode)
        if mask is None:
            block.kind = BranchKind.FALL
            if block.end in blocks:
                block.successors.append(block.end)
                blocks[block.end].predecessors.append(addr)
            continue

        is_unconditional = opcode is Op.Nop
        has_explicit_target = False

        for i in range(6):
            if not mask:
                break
            if mask & 1:
                target = _resolve_param(insn.arguments[i])
                if target is not None and target in blocks:
                    if target not in block.successors:
                        block.successors.append(target)
                        blocks[target].predecessors.append(addr)
                    has_explicit_target = True
                elif target is None and not is_unconditional:
                    if block.end in blocks and block.end not in block.successors:
                        block.successors.append(block.end)
                        blocks[block.end].predecessors.append(addr)
            mask >>= 1

        if is_unconditional:
            block.kind = BranchKind.JUMP if has_explicit_target else BranchKind.FALL
            if not has_explicit_target and block.end in blocks:
                block.successors.append(block.end)
                blocks[block.end].predecessors.append(addr)
        else:
            block.kind = BranchKind.CONDITIONAL
            if block.end in blocks and block.end not in block.successors:
                block.successors.append(block.end)
                blocks[block.end].predecessors.append(addr)

    return blocks


def linearize(
    header: NSHeader,
    _cfg: dict[int, BasicBlock],
    labels: list[int],
    start: int,
    end: int,
) -> BlockNode:
    """
    Trivially convert a CFG into a flat BlockNode. No pattern matching is performed;
    every instruction becomes an InstructionNode, BranchNode, GotoNode, or ReturnNode,
    and labels are inserted as LabelNode where needed.

    This is the identity transform: rendering this BlockNode produces the same output
    as the flat instruction iteration.
    """
    from refinery.lib.nsis.decompiler import CMD_REF_Goto
    nodes: list[NSNode] = []
    for addr in range(start, end):
        if labels[addr] & CMD_REF_Goto:
            nodes.append(LabelNode(addr))
        insn = header.instructions[addr]
        opcode = header.opcode(insn)
        if opcode is Op.Ret:
            nodes.append(ReturnNode(addr))
        elif opcode is Op.Nop and insn.arguments[0] != 0:
            nodes.append(GotoNode(addr, insn.arguments[0]))
        elif opcode in _GOTO_MASKS and opcode is not Op.Nop:
            nodes.append(BranchNode(addr, opcode))
        else:
            nodes.append(InstructionNode(addr, opcode))
    return BlockNode(nodes)


def _decode_branch_targets(
    header: NSHeader, address: int,
) -> tuple[int | None, int | None]:
    """
    For a conditional branch instruction, decode the two primary targets:
    (fall_through_or_true, forward_or_false).

    Returns (true_target, false_target) where each is an instruction address or None
    for fall-through. The semantics depend on the opcode:
    - StrCmp: args[2]=equal (true), args[3]=not-equal (false)
    - IntCmp: args[2]=equal, args[3]=less, args[4]=greater (multi-way)
    - IfFileExists: args[1]=exists (true), args[2]=not-exists (false)
    - IfFlag: args[0]=set (true), args[1]=clear (false)
    - IsWindow: args[1]=is-window (true), args[2]=not-window (false)
    - MessageBox: args[3]=button1, args[5]=button2 (multi-way, not reduced)
    """
    insn = header.instructions[address]
    opcode = header.opcode(insn)
    args = insn.arguments

    if opcode is Op.StrCmp:
        return _resolve_param(args[2]), _resolve_param(args[3])
    if opcode is Op.IfFileExists:
        return _resolve_param(args[1]), _resolve_param(args[2])
    if opcode is Op.IfFlag:
        return _resolve_param(args[0]), _resolve_param(args[1])
    if opcode is Op.IsWindow:
        return _resolve_param(args[1]), _resolve_param(args[2])
    if opcode is Op.IntCmp:
        equal = _resolve_param(args[2])
        less = _resolve_param(args[3])
        greater = _resolve_param(args[4])
        if equal is not None:
            other = less if less is not None else greater
            return equal, other
        return less, greater
    return None, None


def _build_addr_index(body: list[NSNode]) -> dict[int, int]:
    """
    Build a mapping from instruction/label address to index in the body list.
    For IfNode/WhileNode/DoWhileNode, maps the condition/first address.
    """
    addr_to_idx: dict[int, int] = {}
    for i, node in enumerate(body):
        if isinstance(node, (InstructionNode, BranchNode, GotoNode, ReturnNode)):
            addr_to_idx.setdefault(node.address, i)
        elif isinstance(node, LabelNode):
            addr_to_idx.setdefault(node.address, i)
        elif isinstance(node, IfNode):
            addr_to_idx.setdefault(node.condition.address, i)
        elif isinstance(node, WhileNode):
            addr_to_idx.setdefault(node.condition.address, i)
        elif isinstance(node, DoWhileNode):
            addr_to_idx.setdefault(node.condition.address, i)
    return addr_to_idx


def reduce_loops(root: BlockNode, header: NSHeader) -> BlockNode:
    """
    Scan a linearized BlockNode for loop patterns and replace matched sequences
    with WhileNode or DoWhileNode structures.

    Recognizes:
    - While (test at top): A conditional branch header followed by a body that ends with
      an unconditional Goto back to the header. The branch's forward exit is past the Goto.
    - Do/While (test at bottom): A body starting at a label, followed by a conditional
      branch whose one target jumps back to the label.

    Loops are reduced innermost-first by iterating until no more reductions are found.
    """
    body = list(root.body)
    addr_to_idx = _build_addr_index(body)

    changed = True
    while changed:
        changed = False
        new_body: list[NSNode] = []
        body_idx_to_new: dict[int, int] = {}
        consumed: set[int] = set()
        i = 0
        while i < len(body):
            node = body[i]

            if isinstance(node, GotoNode):
                target_addr = _resolve_param(node.target)

                if (
                    target_addr is not None
                    and target_addr < node.address
                    and target_addr in addr_to_idx
                ):
                    header_idx = addr_to_idx[target_addr]
                    if header_idx not in consumed:
                        new_idx = body_idx_to_new.get(header_idx, header_idx)
                        cond_node = None
                        cond_idx = 0
                        negated = False
                        for scan in range(header_idx, i):
                            candidate = body[scan]
                            if isinstance(candidate, BranchNode) and candidate.opcode is not Op.MessageBox:
                                true_t, false_t = _decode_branch_targets(header, candidate.address)
                                fall_through = candidate.address + 1
                                if true_t is None:
                                    true_t = fall_through
                                if false_t is None:
                                    false_t = fall_through
                                exit_target = None
                                negated = False
                                if true_t > node.address:
                                    exit_target = true_t
                                    negated = True
                                elif false_t > node.address:
                                    exit_target = false_t
                                    negated = False
                                if exit_target is not None:
                                    cond_node = candidate
                                    cond_idx = scan
                                    break

                        if cond_node is not None:
                            preamble = body[header_idx:cond_idx]
                            loop_body_nodes = body[cond_idx + 1:i]
                            loop_body = BlockNode(list(loop_body_nodes))
                            while_node = WhileNode(
                                condition=cond_node,
                                body=reduce_loops(loop_body, header),
                                negated=negated,
                            )
                            consumed.update(range(header_idx, i + 1))
                            if new_idx < len(new_body):
                                new_body = new_body[:new_idx]
                            new_body.extend(preamble)
                            new_body.append(while_node)
                            i += 1
                            changed = True
                            continue

            if isinstance(node, BranchNode) and node.opcode is not Op.MessageBox:
                true_t, false_t = _decode_branch_targets(header, node.address)
                fall_through = node.address + 1
                if true_t is None:
                    true_t = fall_through
                if false_t is None:
                    false_t = fall_through

                back_target = None
                negated = False
                if true_t < node.address and true_t in addr_to_idx:
                    back_target = true_t
                    negated = False
                elif false_t < node.address and false_t in addr_to_idx:
                    back_target = false_t
                    negated = True

                if back_target is not None:
                    header_idx = addr_to_idx[back_target]
                    if header_idx not in consumed:
                        new_idx = body_idx_to_new.get(header_idx, header_idx)
                        loop_body_nodes = body[header_idx:i]
                        if loop_body_nodes:
                            loop_body = BlockNode(list(loop_body_nodes))
                            do_while_node = DoWhileNode(
                                body=reduce_loops(loop_body, header),
                                condition=node,
                                negated=negated,
                            )
                            consumed.update(range(header_idx, i + 1))
                            if new_idx < len(new_body):
                                new_body = new_body[:new_idx]
                            new_body.append(do_while_node)
                            i += 1
                            changed = True
                            continue

            body_idx_to_new[i] = len(new_body)
            new_body.append(node)
            i += 1

        body = new_body
        addr_to_idx = _build_addr_index(body)

    return BlockNode(body)


def reduce_if_else(root: BlockNode, header: NSHeader) -> BlockNode:
    """
    Scan a linearized BlockNode for If/Else patterns and replace matched sequences
    with IfNode structures. Unmatched patterns are left as-is.

    Recognizes:
    - Triangle: conditional branch has one forward-jump target, body falls through to it.
    - Diamond: conditional branch has one forward-jump target, body ends with Goto past it,
      creating then-body and else-body regions.
    """
    body = list(root.body)
    addr_to_idx = _build_addr_index(body)

    changed = True
    while changed:
        changed = False
        new_body: list[NSNode] = []
        i = 0
        while i < len(body):
            node = body[i]
            if not isinstance(node, BranchNode):
                new_body.append(node)
                i += 1
                continue

            true_target, false_target = _decode_branch_targets(header, node.address)

            if node.opcode is Op.MessageBox:
                new_body.append(node)
                i += 1
                continue

            fall_through = node.address + 1
            if true_target is None:
                true_target = fall_through
            if false_target is None:
                false_target = fall_through

            true_fwd = true_target > node.address and true_target != fall_through
            false_fwd = false_target > node.address and false_target != fall_through

            if true_fwd and false_fwd:
                if true_target <= false_target:
                    forward_target = true_target
                    negated = True
                else:
                    forward_target = false_target
                    negated = False
            elif false_fwd:
                forward_target = false_target
                negated = False
            elif true_fwd:
                forward_target = true_target
                negated = True
            else:
                new_body.append(node)
                i += 1
                continue

            if forward_target not in addr_to_idx:
                new_body.append(node)
                i += 1
                continue

            merge_idx = addr_to_idx[forward_target]
            then_start = i + 1
            then_nodes = body[then_start:merge_idx]

            if not then_nodes:
                new_body.append(node)
                i += 1
                continue

            has_instruction = any(
                isinstance(n, (InstructionNode, GotoNode, ReturnNode))
                for n in then_nodes
            )
            if not has_instruction:
                new_body.append(node)
                i += 1
                continue

            last_then_idx = len(then_nodes) - 1
            while last_then_idx >= 0 and isinstance(then_nodes[last_then_idx], LabelNode):
                last_then_idx -= 1
            last_then = then_nodes[last_then_idx] if last_then_idx >= 0 else None
            if isinstance(last_then, GotoNode):
                goto_target_addr = _resolve_goto_target(header, last_then.address)
                if goto_target_addr is not None and goto_target_addr > forward_target:
                    if goto_target_addr in addr_to_idx:
                        else_end_idx = addr_to_idx[goto_target_addr]
                        trailing_labels = then_nodes[last_then_idx + 1:]
                        else_nodes = trailing_labels + body[merge_idx:else_end_idx]
                        then_inner = then_nodes[:last_then_idx]
                        if_node = IfNode(
                            condition=node,
                            then_body=reduce_if_else(BlockNode(list(then_inner)), header),
                            else_body=reduce_if_else(BlockNode(list(else_nodes)), header),
                            negated=negated,
                        )
                        new_body.append(if_node)
                        i = else_end_idx
                        changed = True
                        continue

            if_node = IfNode(
                condition=node,
                then_body=reduce_if_else(BlockNode(list(then_nodes)), header),
                negated=negated,
            )
            new_body.append(if_node)
            i = merge_idx
            changed = True
            continue

        body = new_body
        addr_to_idx = _build_addr_index(body)

    return BlockNode(body)


def eliminate_dead_code(root: BlockNode) -> BlockNode:
    """
    Remove unreachable nodes after unconditional control transfers (Goto, Return).
    A LabelNode re-establishes reachability since it may be a jump target from elsewhere.
    Compound nodes (If, While, DoWhile, Block) also break dead zones because they may
    contain reachable labels.
    Recurses into compound node bodies.
    """
    new_body: list[NSNode] = []
    dead = False
    for node in root.body:
        if dead:
            if isinstance(node, LabelNode):
                dead = False
                new_body.append(node)
            elif isinstance(node, (BlockNode, IfNode, WhileNode, DoWhileNode)):
                dead = False
                node = _eliminate_in_node(node)
                new_body.append(node)
            continue
        node = _eliminate_in_node(node)
        new_body.append(node)
        if isinstance(node, (GotoNode, ReturnNode)):
            dead = True
    return BlockNode(new_body)


def _eliminate_in_node(node: NSNode) -> NSNode:
    if isinstance(node, BlockNode):
        return eliminate_dead_code(node)
    if isinstance(node, IfNode):
        then_body = eliminate_dead_code(node.then_body)
        else_body = eliminate_dead_code(node.else_body) if node.else_body else None
        return IfNode(node.condition, then_body, else_body, node.negated)
    if isinstance(node, WhileNode):
        return WhileNode(node.condition, eliminate_dead_code(node.body), node.negated)
    if isinstance(node, DoWhileNode):
        return DoWhileNode(eliminate_dead_code(node.body), node.condition, node.negated)
    return node


def _resolve_goto_target(header: NSHeader, address: int) -> int | None:
    """
    Resolve the target of a Nop/Goto instruction.
    """
    return _resolve_param(header.instructions[address].arguments[0])


def walk_addresses(node: NSNode) -> list[int]:
    """
    Collect all instruction addresses from an IR tree in order.
    Labels are not included since they don't correspond to actual instructions.
    """
    result: list[int] = []
    if isinstance(node, BlockNode):
        for child in node.body:
            result.extend(walk_addresses(child))
    elif isinstance(node, IfNode):
        result.extend(walk_addresses(node.condition))
        result.extend(walk_addresses(node.then_body))
        if node.else_body is not None:
            result.extend(walk_addresses(node.else_body))
    elif isinstance(node, (WhileNode, DoWhileNode)):
        if isinstance(node, WhileNode):
            result.extend(walk_addresses(node.condition))
            result.extend(walk_addresses(node.body))
        else:
            result.extend(walk_addresses(node.body))
            result.extend(walk_addresses(node.condition))
    elif isinstance(node, LabelNode):
        pass
    elif isinstance(node, (InstructionNode, BranchNode, GotoNode, ReturnNode)):
        result.append(node.address)
    return result


def _render_param(header: NSHeader, param: int) -> str:
    """
    Resolve an instruction parameter to its string representation.
    """
    from refinery.lib.nsis.decompiler import _is_bare_identifier, _is_numeric, nsis_escape
    s = header._read_string(param)
    if s is not None:
        s = nsis_escape(s)
        if _is_bare_identifier(s) or _is_numeric(s):
            return s
        return F'"{s}"'
    return str(param)


def _render_condition_comment(header: NSHeader, branch: BranchNode, negated: bool) -> str:
    """
    Produce a short human-readable condition comment for a structured branch.
    Used as a suffix comment on the branch instruction line.
    """
    from refinery.lib.nsis.decompiler import decode_exec_flags
    insn = header.instructions[branch.address]
    args = insn.arguments

    if branch.opcode is Op.StrCmp:
        left = _render_param(header, args[0])
        right = _render_param(header, args[1])
        case_sensitive = args[4] != 0
        if negated:
            op = 'S!=' if case_sensitive else '!='
        else:
            op = 'S==' if case_sensitive else '=='
        return F'{left} {op} {right}'

    if branch.opcode is Op.IntCmp:
        left = _render_param(header, args[0])
        right = _render_param(header, args[1])
        equal = _resolve_param(args[2])
        less = _resolve_param(args[3])
        greater = _resolve_param(args[4])
        fall = branch.address + 1
        eq_stays = equal is None or equal == fall
        lt_stays = less is None or less == fall
        gt_stays = greater is None or greater == fall
        if negated:
            eq_stays = not eq_stays
            lt_stays = not lt_stays
            gt_stays = not gt_stays
        if eq_stays and lt_stays and not gt_stays:
            return F'{left} <= {right}'
        if eq_stays and not lt_stays and gt_stays:
            return F'{left} >= {right}'
        if eq_stays and not lt_stays and not gt_stays:
            return F'{left} = {right}'
        if not eq_stays and lt_stays and gt_stays:
            return F'{left} != {right}'
        if not eq_stays and lt_stays and not gt_stays:
            return F'{left} < {right}'
        if not eq_stays and not lt_stays and gt_stays:
            return F'{left} > {right}'
        return F'{left} = {right}'

    if branch.opcode is Op.IfFileExists:
        path = _render_param(header, args[0])
        if negated:
            return F'not FileExists {path}'
        return F'FileExists {path}'

    if branch.opcode is Op.IfFlag:
        flag_name = decode_exec_flags(args[2])
        if negated:
            return F'not {flag_name}'
        return flag_name

    if branch.opcode is Op.IsWindow:
        handle = _render_param(header, args[0])
        if negated:
            return F'not IsWindow {handle}'
        return F'IsWindow {handle}'

    return ''


def _render_branch_instruction(
    writer: NSScriptWriter,
    header: NSHeader,
    branch: BranchNode,
    labels: list[int],
    raw: bytes,
    overwrite_state: list[int],
    commented: bool,
) -> None:
    """
    Render a branch instruction using the standard opcode renderer.
    """
    from refinery.lib.nsis.decompiler import render_opcode
    instruction = header.instructions[branch.address]
    writer.tab(commented)
    render_opcode(
        writer, header, instruction, branch.opcode, labels, raw,
        overwrite_state, branch.address, commented,
    )


def render_node(
    node: NSNode,
    writer: NSScriptWriter,
    header: NSHeader,
    labels: list[int],
    raw: bytes,
    overwrite_state: list[int],
    end_comment_index: int,
) -> None:
    """
    Walk an IR tree and render it as NSIS script with structural annotations.

    Recognized control flow constructs are rendered with the original branch
    instruction followed by indented bodies and comment markers for the construct
    boundaries (Else, EndIf, EndWhile, etc.). Unrecognized patterns fall back
    to raw Goto+label output.
    """
    from refinery.lib.nsis.decompiler import (
        CMD_REF_Goto,
        _add_goto_var,
        render_opcode,
    )

    if isinstance(node, BlockNode):
        for child in node.body:
            render_node(child, writer, header, labels, raw, overwrite_state, end_comment_index)

    elif isinstance(node, IfNode):
        commented = node.condition.address < end_comment_index
        condition_comment = _render_condition_comment(header, node.condition, node.negated)
        _render_branch_instruction(
            writer, header, node.condition, labels, raw, overwrite_state, commented,
        )
        writer.small_space_comment()
        writer.write(F'If: {condition_comment}')
        writer.newline()
        writer.indent()
        render_node(node.then_body, writer, header, labels, raw, overwrite_state, end_comment_index)
        writer.dedent()
        if node.else_body is not None and node.else_body.body:
            writer.tab()
            writer.write('; Else')
            writer.newline()
            writer.indent()
            render_node(
                node.else_body, writer, header, labels, raw,
                overwrite_state, end_comment_index,
            )
            writer.dedent()
        writer.tab()
        writer.write('; EndIf')
        writer.newline()

    elif isinstance(node, WhileNode):
        commented = node.condition.address < end_comment_index
        condition_comment = _render_condition_comment(header, node.condition, node.negated)
        _render_branch_instruction(
            writer, header, node.condition, labels, raw, overwrite_state, commented,
        )
        writer.small_space_comment()
        writer.write(F'While: {condition_comment}')
        writer.newline()
        writer.indent()
        render_node(node.body, writer, header, labels, raw, overwrite_state, end_comment_index)
        writer.dedent()
        writer.tab()
        writer.write('; EndWhile')
        writer.newline()

    elif isinstance(node, DoWhileNode):
        writer.tab()
        writer.write('; Do')
        writer.newline()
        writer.indent()
        render_node(node.body, writer, header, labels, raw, overwrite_state, end_comment_index)
        writer.dedent()
        commented = node.condition.address < end_comment_index
        condition_comment = _render_condition_comment(header, node.condition, node.negated)
        _render_branch_instruction(
            writer, header, node.condition, labels, raw, overwrite_state, commented,
        )
        writer.small_space_comment()
        if node.negated:
            writer.write(F'LoopUntil: {condition_comment}')
        else:
            writer.write(F'LoopWhile: {condition_comment}')
        writer.newline()

    elif isinstance(node, LabelNode):
        if labels[node.address] & CMD_REF_Goto:
            writer.write(F'label_{node.address}:')
            writer.newline()

    elif isinstance(node, ReturnNode):
        writer.tab_string('Return')
        writer.newline()

    elif isinstance(node, GotoNode):
        instruction = header.instructions[node.address]
        commented = node.address < end_comment_index
        writer.tab(commented)
        writer.write('Goto')
        _add_goto_var(writer, header, instruction.arguments[0])
        writer.newline()

    elif isinstance(node, (InstructionNode, BranchNode)):
        instruction = header.instructions[node.address]
        opcode = node.opcode
        commented = node.address < end_comment_index
        if opcode is Op.INVALID_OPCODE:
            writer.tab(commented)
            writer.write(F'Command{instruction.opcode}')
            writer.newline()
        else:
            writer.tab(commented)
            render_opcode(
                writer, header, instruction, opcode, labels, raw,
                overwrite_state, node.address, commented,
            )
            writer.newline()
