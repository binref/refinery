from __future__ import annotations

import pathlib
import unittest

from setuptools.command.egg_info import FileList

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _shipped_in_the_source_distribution() -> set[str]:
    """
    The files of the package that `MANIFEST.in` puts into the source distribution, chosen by the
    setuptools code that builds one.
    """
    candidates = [path for path in _ROOT.joinpath('refinery').rglob('*') if path.is_file()]
    candidates.extend(path for path in _ROOT.iterdir() if path.is_file())
    files = FileList()
    files.set_allfiles([str(path.relative_to(_ROOT)) for path in candidates])
    for line in _ROOT.joinpath('MANIFEST.in').read_text(encoding='utf8').splitlines():
        if line.strip():
            files.process_template_line(line)
    return {pathlib.PurePath(name).as_posix() for name in files.files}


class TestTheSourceDistribution(unittest.TestCase):

    def test_every_cython_source_of_the_package_is_shipped(self):
        cython = sorted(
            path.relative_to(_ROOT).as_posix()
            for pattern in ('*.pyx', '*.pxd')
            for path in _ROOT.joinpath('refinery').rglob(pattern)
        )
        shipped = _shipped_in_the_source_distribution()
        self.assertListEqual([name for name in cython if name not in shipped], [])
