from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.types import buf
from refinery.units.formats import UnpackResult
from refinery.units.formats.office import VBAUnit, vba_project_folders

if TYPE_CHECKING:
    from refinery.lib.ole.file import OleFileLike


class vbastr(VBAUnit):
    """
    Extract VBA macro variables from Office documents.

    The items are extracted below a folder that is named after their VBA project, followed by the
    form that holds them, for example `Project/UserForm1/Label1/Label1.cap`. When the document
    holds more than one project, every folder is preceded by the number of its project, as with
    `refinery.vbamc`. A control inside a frame comes out below the storage of the frame inside its
    form. A form that belongs to no project whose dir stream can be read, such as the controls on a
    worksheet, comes out below the path of its storage. The stem of their file name is the same as
    the variable's name. The variable
    can define a caption, a control tip text, and a value; the unit extracts these with the
    synthesized file extension "cap", "tip", and "val", respectively. When the controls of a form
    cannot be parsed, the printable strings of its object stream are extracted instead, as `o.val`
    or as `o.v1.val`, `o.v2.val`, and so on. The meta variable `stream` holds the location of the
    object stream.
    """
    def unpack(self, data):
        from refinery.lib.ole.vba import vba_compound_files, vba_form_storages
        names: list[str] = []
        outputs: list[tuple[int | None, str, buf, str]] = []
        for compound_file in vba_compound_files(data, self._skip):
            storages = [(len(names) + k, project.storage) for k, project in enumerate(compound_file.projects)]
            names.extend(project.name for project in compound_file.projects)
            for form in vba_form_storages(compound_file.ole):
                owners = [(len(storage), index, storage) for index, storage in storages if form.startswith(storage)]
                if owners:
                    _, index, storage = max(owners)
                    relative = form[len(storage):]
                else:
                    index, relative = None, form
                location = compound_file.location(F'{form}/o')
                try:
                    variables = self._variables(compound_file.ole, form, location)
                except Exception as error:
                    self._skip(compound_file.location(form), error)
                    continue
                outputs.extend((index, F'{relative}/{path}', value, location) for path, value in variables)
        folders = vba_project_folders(names)
        for index, path, value, location in outputs:
            if index is not None:
                path = F'{folders[index]}/{path}'
            yield UnpackResult(path, value, stream=location)

    def _variables(self, ole: OleFileLike, form: str, location: str) -> list[tuple[str, buf]]:
        from refinery.lib.ole.forms import OleFormParsingError, extract_OleFormVariables
        from refinery.lib.ole.vba import vba_form_strings
        try:
            variables = extract_OleFormVariables(ole, form)
        except OleFormParsingError as error:
            self.log_debug(str(error))
            self.log_info(F'the controls of {location} cannot be parsed; extracting its strings instead')
            strings = vba_form_strings(ole, form)
            if len(strings) == 1:
                return [('o.val', strings[0])]
            return [(F'o.v{k}.val', string) for k, string in enumerate(strings, 1)]
        results: list[tuple[str, buf]] = []
        for variable in variables:
            if not variable:
                continue
            name = variable['name']
            for ext, key in {
                'cap': 'caption',
                'tip': 'control_tip_text',
                'val': 'value',
            }.items():
                if value := self._binary(variable.get(key)):
                    results.append((F'{name}/{name}.{ext}', value))
        return results

    def _binary(self, value: object) -> buf | None:
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray, memoryview)):
            return value
        return str(value).encode(self.codec)
