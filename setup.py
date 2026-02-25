#!/usr/bin/env python3
from __future__ import annotations

import re
import os
import setuptools
import pathlib
import sys
import toml

from contextlib import suppress
from setuptools import Extension
from setuptools.command.build_ext import build_ext as _build_ext


class BuildCommand(_build_ext):
    """
    Custom command that fixes a Windows issue for building Cython extensions: as the setup imports
    refinery modules, loaded Cython extension get loaded and are locked by the OS. The default
    inplace build fails because it cannot overwrite the locked file.
    The workaround renames existing .pyd files before the build. Windows allows renaming open files
    even when they are locked for deletion. After the build, the renamed files are cleaned up on a
    best-effort basis.
    """
    _renamed: dict[str, str] = {}

    def _rename_locked_extensions(self):
        if not self.inplace:
            return
        for ext in self.extensions:
            if not os.path.exists(fullpath := self.get_ext_fullpath(ext.name)):
                continue
            renamed = F'{fullpath}.old'
            with suppress(OSError):
                os.remove(renamed)
            with suppress(OSError):
                os.rename(fullpath, renamed)
                self._renamed[fullpath] = renamed

    def _cleanup_renamed(self):
        for renamed in self._renamed.values():
            with suppress(OSError):
                os.remove(renamed)

    def run(self):
        self._renamed.clear()
        self._rename_locked_extensions()
        try:
            _build_ext.run(self)
        finally:
            self._cleanup_renamed()


__prefix__ = os.getenv('REFINERY_PREFIX') or ''
__minver__ = '3.8'
__github__ = 'https://github.com/binref/refinery/'
__gitraw__ = 'https://raw.githubusercontent.com/binref/refinery/'
__author__ = 'Jesko Huettenhain'
__slogan__ = 'A toolkit to transform and refine (mostly) binary data.'
__topics__ = [
    'Development Status :: 3 - Alpha',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 3 :: Only',
    'Topic :: Security',
    'Topic :: Security :: Cryptography',
    'Topic :: System :: Archiving :: Compression'
]

EXTENSION_DICT = {
    'refinery.lib.fast.a3x'       : 'refinery/lib/fast/a3x.pyx',
    'refinery.lib.fast.zipcrypto' : 'refinery/lib/fast/zipcrypto.pyx',
    'refinery.lib.seven.deflate'  : 'refinery/lib/seven/deflate.pyx',
    'refinery.lib.seven.huffman'  : 'refinery/lib/seven/huffman.pyx',
    'refinery.lib.seven.lzx'      : 'refinery/lib/seven/lzx.pyx',
}

EXTENSION_LIST = [
    Extension(key, [value]) for key, value in EXTENSION_DICT.items()]


class DisableExtCommand(setuptools.Command):
    description = 'Rename all in-place Cython extensions to .old so they are not loaded.'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        count = 0
        for ext in EXTENSION_LIST:
            name = ext.name
            # Compute the expected filename for this platform
            fullpath = os.path.join(*name.split('.'))
            import importlib.machinery
            for suffix in importlib.machinery.EXTENSION_SUFFIXES:
                candidate = fullpath + suffix
                if os.path.exists(candidate):
                    renamed = F'{candidate}.old'
                    with suppress(OSError):
                        os.remove(renamed)
                    try:
                        os.rename(candidate, renamed)
                        print(F'disabled: {candidate} -> {renamed}')
                        count += 1
                    except OSError as e:
                        print(F'failed to disable {candidate}: {e}')
        if count:
            print(F'Disabled {count} extension(s).')
        else:
            print('No extensions found to disable.')


class EnableExtCommand(setuptools.Command):
    description = 'Restore previously disabled (.old) Cython extensions.'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        count = 0
        for ext in EXTENSION_LIST:
            name = ext.name
            fullpath = os.path.join(*name.split('.'))
            import importlib.machinery
            for suffix in importlib.machinery.EXTENSION_SUFFIXES:
                candidate = fullpath + suffix + '.old'
                if os.path.exists(candidate):
                    original = fullpath + suffix
                    with suppress(OSError):
                        os.remove(original)
                    try:
                        os.rename(candidate, original)
                        print(F'enabled: {candidate} -> {original}')
                        count += 1
                    except OSError as e:
                        print(F'failed to enable {candidate}: {e}')
        if count:
            print(F'Enabled {count} extension(s).')
        else:
            print('No disabled extensions found to restore.')


class DeployCommand(setuptools.Command):
    description = 'Tag and push new release.'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    @staticmethod
    def main():
        import subprocess
        import shlex
        import refinery
        import os

        from pathlib import Path

        DEVNULL = open(os.devnull, 'wb')

        def run(cmd):
            print(F'run: {cmd}')
            return subprocess.check_call(
                shlex.split(cmd),
                stdout=DEVNULL,
                stderr=DEVNULL,
                cwd=os.getcwd(),
            )

        root = Path(refinery.__file__).parent.parent
        os.chdir(root)

        try:
            run(F'git tag {refinery.__version__}')
            run(R'git push')
            run(R'git push --tags')
        except subprocess.CalledProcessError as E:
            print(F'error: {E!s}')
            return 1
        else:
            return 0

    def run(self):
        sys.exit(self.main())


def get_config():
    sys.path.insert(0, str(pathlib.Path(__file__).parent.absolute()))

    import refinery
    import refinery.lib.shared

    import importlib
    import pkgutil

    with refinery.__unit_loader__ as ldr:
        ldr.reload()

    for _, name, _ in pkgutil.iter_modules(refinery.lib.shared.__path__):
        # populate all shared dependencies
        importlib.import_module(F'refinery.lib.shared.{name}')

    def get_setup_extras(requirements: list[str] | None = None):
        all_optional: set[str] = set()
        all_required: set[str] = set()
        extras: dict[str, set[str]] = {'all': all_optional}
        with refinery.__unit_loader__ as ldr:
            for executable in (
                refinery.lib.shared.GlobalDependenciesDummy,
                *ldr.cache.values()
            ):
                if executable.optional_dependencies:
                    for key, deps in executable.optional_dependencies.items():
                        bucket = extras.setdefault(key, set())
                        bucket.update(deps)
                        all_optional.update(deps)
                if executable.required_dependencies:
                    all_required.update(executable.required_dependencies)
        if requirements is not None:
            requirements.extend(all_required)
        return {k: list(v) for k, v in extras.items()}

    def get_setup_readme(filename: str | pathlib.Path | None = None):
        if filename is None:
            filename = pathlib.Path(__file__).parent.joinpath('README.md')
        with open(filename, 'r', encoding='UTF8') as README:
            def complete_link(match):
                link: str = match[1]
                if any(link.lower().endswith(xt) for xt in ('jpg', 'gif', 'png', 'svg')):
                    return F'({__gitraw__}master/{link})'
                else:
                    return F'({__github__}blob/master/{link})'
            readme = README.read()
            return re.sub(R'(?<=\])\((?!\w+://)(.*?)\)', complete_link, readme)

    def get_setup_common() -> dict:
        return dict(
            version=refinery.__version__,
            long_description=get_setup_readme(),
            author=__author__,
            description=__slogan__,
            long_description_content_type='text/markdown',
            url=__github__,
            python_requires=F'>={__minver__}',
            classifiers=__topics__,
        )

    def normalize_name(name: str, separator: str = '-'):
        return separator.join([segment for segment in name.strip('_').split('_')])

    if __prefix__ == '!':
        console_scripts = []
    else:
        with refinery.__unit_loader__ as ldr:
            console_scripts = [
                F'{__prefix__}{normalize_name(name)}={path}:{name}.run'
                for name, path in ldr.units.items()
            ]
    console_scripts.append('binref=refinery.explore:explorer')
    settings = get_setup_common()
    settings['classifiers'] += [
        'Topic :: System :: Shells',
        'Topic :: Utilities'
    ]

    ppcfg: dict[str, dict[str, list[str]]] = toml.load('pyproject.toml')
    requirements = ppcfg['build-system']['requires']

    magic = 'python-magic'
    if os.name == 'nt':
        magic = F'{magic}-win64'
    requirements.append(magic)

    extras = get_setup_extras(requirements)
    config = get_setup_common()

    try:
        import Cython.Build as cy
        ext = cy.cythonize(EXTENSION_LIST)
    except Exception:
        ext = []

    config.update(
        name=refinery.__distribution__,
        packages=setuptools.find_packages(include=('refinery*',)),
        install_requires=requirements,
        extras_require=extras,
        include_package_data=True,
        entry_points={'console_scripts': console_scripts},
        cmdclass={
            'deploy': DeployCommand,
            'build_ext': BuildCommand,
            'disable_ext': DisableExtCommand,
            'enable_ext': EnableExtCommand,
        },
        ext_modules=ext,
    )

    return config


if __name__ == '__main__':
    setuptools.setup(**get_config())
