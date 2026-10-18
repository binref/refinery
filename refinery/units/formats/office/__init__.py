"""
These units process data formats related to Microsoft Office.
"""
from __future__ import annotations

import abc

from typing import TYPE_CHECKING, Callable

from refinery.lib.tools import exception_to_string
from refinery.units.formats import PathExtractorUnit, UnpackResult

if TYPE_CHECKING:
    from refinery.lib.ole.vba import VBAModule, VBAProject


def vba_project_folders(names: list[str]) -> list[str]:
    """
    The folders for VBA projects with the given names, in their order. The folder of a project is
    its name as stored; when there is more than one project, the number of the project, counted
    from one, precedes the name of every folder. Names are never compared, so two projects with
    the same name get different folders. A name that holds a path separator or consists of dots
    is used as stored and resolved like every extracted path.
    """
    if len(names) < 2:
        return list(names)
    return [F'{number}/{name}' for number, name in enumerate(names, 1)]


class VBAUnit(PathExtractorUnit, abstract=True):
    """
    The base of units that extract data from the VBA projects in an Office document. Outputs of a
    project are extracted below the folder of the project, as given by `vba_project_folders`. The
    meta variable `stream` holds the location of the stream that an output comes from: the part of
    the document that holds the compound file, followed by the path of the stream inside it. A part
    or project that cannot be read is skipped with a warning that names its location.
    """
    @classmethod
    def handles(cls, data) -> bool:
        from refinery.lib.ole.vba import is_vba_container
        return is_vba_container(data)

    def _skip(self, location: str, error: Exception):
        self.log_warn(F'skipping {location}: {exception_to_string(error)}')


class VBAModuleUnit(VBAUnit, abstract=True):
    """
    The base of units that extract one output for every module of the VBA projects in an Office
    document, under the name of the module stream. A module that cannot be read is skipped with a
    warning; when a module record of a dir stream cannot be read, the modules in front of it are
    still extracted.
    """
    @abc.abstractmethod
    def _module_reader(self, project: VBAProject) -> Callable[[VBAModule], str | None]:
        """
        A function that returns the output for a module of the given project, or `None` when the
        module has no output.
        """
        raise NotImplementedError

    def unpack(self, data):
        from refinery.lib.ole.vba import vba_projects
        projects: list[tuple[str, list[tuple[VBAModule, str]]]] = []
        for project in vba_projects(data, self._skip):
            outputs: list[tuple[VBAModule, str]] = []
            projects.append((project.name, outputs))
            try:
                read = self._module_reader(project)
            except Exception as error:
                self._skip(project.location(F'{project.storage}VBA'), error)
                continue
            modules: list[VBAModule] = []
            try:
                for module in project.modules():
                    modules.append(module)
            except Exception as error:
                self._skip(project.location(project.dir_path), error)
            for module in modules:
                try:
                    output = read(module)
                except Exception as error:
                    self._skip(module.location, error)
                    continue
                if output:
                    outputs.append((module, output))
        folders = vba_project_folders([name for name, _ in projects])
        for folder, (_, outputs) in zip(folders, projects):
            for module, output in outputs:
                yield UnpackResult(F'{folder}/{module.name}', output.encode(self.codec), stream=module.location)
