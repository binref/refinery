"""
The system commands of the macro language: the external calls the program makes, the files it
opens and writes, the environment answers its questions read, and the Kernel32 pseudo-commands
that allocate and fill the memory of the emulated process.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.formula.model import XlMissingArgument
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.trace import XlmStatus
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmValue, is_number, wrap_literal

if TYPE_CHECKING:
    from refinery.lib.excel.formula.model import XlFunctionCall
    from refinery.lib.scripts.xlm.engine import XlmEngine
    from refinery.lib.scripts.xlm.references import XlmCursor

_DIRECTORY = R'C:\Users\user\Documents'


def _partial(spelled: str) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=spelled, partial=True))


def _arguments(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> list[XlmValue]:
    """
    The values of the arguments a call spells, a missing argument left out — the grammar of the
    retiring port did not materialize one at all.
    """
    return [
        evaluate_expression(engine, node, cursor)
        for node in call.arguments
        if not isinstance(node, XlMissingArgument)
    ]


def _call(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    arguments = _arguments(engine, call, cursor)
    partial = any(argument.partial for argument in arguments)
    return XlmOutcome(value=XlmValue(
        value=0,
        text=F'CALL({",".join(argument.text or "" for argument in arguments)})',
        partial=partial,
    ))


def _register(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    if len(call.arguments) < 4:
        return XlmOutcome(
            value=XlmValue(value=0, text=synthesize_formula(call)),
            status=XlmStatus.Error,
        )
    arguments = _arguments(engine, call, cursor)
    engine.aliases[arguments[3].unwrap()] = F'{arguments[0].unwrap()}.{arguments[1].unwrap()}'
    return XlmOutcome(value=XlmValue(
        value=0,
        text=F'REGISTER({",".join(argument.text or "" for argument in arguments)})',
    ))


def _register_id(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    if len(call.arguments) < 3:
        return XlmOutcome(
            value=XlmValue(value=0, text=synthesize_formula(call)),
            status=XlmStatus.Error,
        )
    arguments = _arguments(engine, call, cursor)
    return XlmOutcome(value=XlmValue(
        value=F'{arguments[0].unwrap()}.{arguments[1].unwrap()}',
        text=F'REGISTER.ID({",".join(argument.text or "" for argument in arguments)})',
    ))


def _fopen(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    name = evaluate_expression(engine, call.arguments[0], cursor)
    access = '1'
    if len(call.arguments) > 1:
        access = str(evaluate_expression(engine, call.arguments[1], cursor).value)
    file_name = name.unwrap() if not name.partial else 'default_name'
    engine.files.open(file_name, access)
    return XlmOutcome(value=XlmValue(
        value=file_name,
        text=F'FOPEN({name.text},{access})',
        partial=name.partial,
    ))


def _fsize(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    name = evaluate_expression(engine, call.arguments[0], cursor)
    if name.partial:
        return _partial(spelled)
    file_name = name.unwrap()
    size = engine.files.size(file_name)
    if size is None:
        return XlmOutcome(value=XlmValue(
            value=0,
            text=F'FSIZE({wrap_literal(file_name)})',
            partial=True,
        ))
    return XlmOutcome(value=XlmValue(
        value=size,
        text=F'FSIZE({wrap_literal(file_name)})',
    ))


def _fwrite(
    engine: XlmEngine,
    call: XlFunctionCall,
    cursor: XlmCursor,
    line: str = '',
) -> XlmOutcome:
    name = evaluate_expression(engine, call.arguments[0], cursor)
    content = evaluate_expression(engine, call.arguments[1], cursor)
    file_name = str(name.value)
    if not file_name.strip() or is_number(file_name):
        file_name = engine.files.first()
    written = content.unwrap()
    took = engine.files.write(file_name, F'{written}{line}')
    return XlmOutcome(value=XlmValue(
        value=0,
        text=F'FWRITE({wrap_literal(file_name)},{wrap_literal(written)})',
        partial=not took,
    ))


def _fwriteln(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return _fwrite(engine, call, cursor, '\r\n')


def _files(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    name = evaluate_expression(engine, call.arguments[0], cursor)
    directory = name.unwrap()
    return XlmOutcome(value=XlmValue(
        value=directory,
        text=F'FILES({wrap_literal(directory)})',
    ))


def _directory(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=_DIRECTORY, text=_DIRECTORY))


def _error(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=0, text=synthesize_formula(call)))


def _app_maximize(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=True))


def _get_workspace(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if len(call.arguments) != 1:
        return _partial(spelled)
    number = evaluate_expression(engine, call.arguments[0], cursor)
    if number.partial or not is_number(number.text):
        return _partial(spelled)
    answer = engine.environment.workspace(int(float(number.unwrap())))
    return XlmOutcome(value=XlmValue(
        value=answer,
        text=F'GET.WORKSPACE({number.text})',
    ))


def _get_window(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if len(call.arguments) != 1:
        return XlmOutcome(value=XlmValue(value='', text=spelled), status=XlmStatus.Error)
    number = evaluate_expression(engine, call.arguments[0], cursor)
    if number.partial or not is_number(number.text):
        return XlmOutcome(value=XlmValue(
            value='',
            text=F'GET.WINDOW({number.text})',
            partial=True,
        ))
    index = int(float(number.unwrap()))
    answer = engine.environment.window_value(
        index,
        engine.view.workbook_name,
        cursor.sheet,
    )
    window = engine.environment.window(index)
    return XlmOutcome(value=XlmValue(
        value=answer,
        text=str(window) if window is not None else None,
    ))


def _get_document(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    number = evaluate_expression(engine, call.arguments[0], cursor)
    if number.partial or not is_number(number.value):
        return XlmOutcome(value=XlmValue(value='', text=spelled), status=XlmStatus.Error)
    index = int(float(number.value))
    answer = engine.environment.document(
        index,
        engine.view.workbook_name,
        cursor.sheet,
    )
    if answer is None:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=answer, text=answer))


def _get_cell(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return _partial(synthesize_formula(call))


def _virtual_alloc(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    base = evaluate_expression(engine, call.arguments[0], cursor)
    size = evaluate_expression(engine, call.arguments[1], cursor)
    if (
        base.partial
        or size.partial
        or not is_number(base.value)
        or not is_number(size.value)
    ):
        return _partial(spelled)
    address = engine.memory.allocate(int(float(base.value)), int(float(size.value)))
    return XlmOutcome(value=XlmValue(value=address, text=spelled))


def _write_process_memory(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if len(call.arguments) <= 4:
        return _partial(spelled)
    arguments = _arguments(engine, call, cursor)
    if any(argument.partial for argument in arguments):
        return _partial(spelled)
    base = int(float(arguments[1].value))
    data = bytes(ord(char) for char in str(arguments[2].value))
    size = int(float(arguments[3].value))
    if not engine.memory.write(base, data, size):
        return XlmOutcome(
            value=XlmValue(value=0, text=spelled),
            status=XlmStatus.Error,
        )
    return XlmOutcome(value=XlmValue(value=0, text=(
        F'Kernel32.WriteProcessMemory({arguments[0].text},{base},'
        F'"{data.hex()}",{size},{arguments[4].text})'
    )))


def _rtl_copy_memory(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if len(call.arguments) != 3:
        return _partial(spelled)
    destination = evaluate_expression(engine, call.arguments[0], cursor)
    source = evaluate_expression(engine, call.arguments[1], cursor)
    size = evaluate_expression(engine, call.arguments[2], cursor)
    if destination.partial or source.partial:
        return _partial(spelled)
    data = bytes(ord(char) for char in str(source.value))
    if not engine.memory.write(int(float(destination.value)), data, len(data)):
        return XlmOutcome(
            value=XlmValue(value=0, text=spelled),
            status=XlmStatus.Error,
        )
    return XlmOutcome(value=XlmValue(value=0, text=(
        F'Kernel32.RtlCopyMemory({destination.text},"{data.hex()}",{size.text})'
    )))


SYSTEM_HANDLERS = {
    'APP.MAXIMIZE': _app_maximize,
    'CALL': _call,
    'DIRECTORY': _directory,
    'ERROR': _error,
    'FILES': _files,
    'FOPEN': _fopen,
    'FSIZE': _fsize,
    'FWRITE': _fwrite,
    'FWRITELN': _fwriteln,
    'GET.CELL': _get_cell,
    'GET.DOCUMENT': _get_document,
    'GET.WINDOW': _get_window,
    'GET.WORKSPACE': _get_workspace,
    'Kernel32.RtlCopyMemory': _rtl_copy_memory,
    'Kernel32.VirtualAlloc': _virtual_alloc,
    'Kernel32.WriteProcessMemory': _write_process_memory,
    'REGISTER': _register,
    'REGISTER.ID': _register_id,
}
