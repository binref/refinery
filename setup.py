#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, List, Optional, Set

import re
import os
import setuptools
import pathlib
import sys
import toml

__prefix__ = os.getenv('REFINERY_PREFIX') or ''
__minver__ = '3.7'
__github__ = 'https://github.com/binref/refinery/'
__gitraw__ = 'https://raw.githubusercontent.com/binref/refinery/'
__author__ = 'Jesko Huettenhain'
__slogan__ = 'A toolkit to transform and refine (mostly) binary data.'
__topics__ = [
    'Development Status :: 3 - Alpha',
    'License :: OSI Approved :: BSD License',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 3 :: Only',
    'Topic :: Security',
    'Topic :: Security :: Cryptography',
    'Topic :: System :: Archiving :: Compression'
]


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
        run(F'git tag {refinery.__version__}')
        run(R'git push')
        run(R'git push --tags')

    def run(self):
        sys.exit(self.main())


def get_config():
    sys.path.insert(0, str(pathlib.Path(__file__).parent.absolute()))

    import refinery

    with refinery.__unit_loader__:
        refinery.__unit_loader__.reload()

    def get_setup_extras(requirements: Optional[List] = None):
        all_optional: Set[str] = set()
        all_required: Set[str] = set()
        extras: Dict[str, Set[str]] = {'all': all_optional}
        with refinery.__unit_loader__:
            for executable in refinery.__unit_loader__.cache.values():
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

    def get_setup_readme(filename: Optional[str] = None):
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
        with refinery.__unit_loader__:
            console_scripts = [
                F'{__prefix__}{normalize_name(name)}={path}:{name}.run'
                for name, path in refinery.__unit_loader__.units.items()
            ]
    console_scripts.append('binref=refinery.explore:explorer')
    settings = get_setup_common()
    settings['classifiers'] += [
        'Topic :: System :: Shells',
        'Topic :: Utilities'
    ]

    ppcfg: Dict[str, Dict[str, List[str]]] = toml.load('pyproject.toml')
    requirements = ppcfg['build-system']['requires']

    magic = 'python-magic'
    if os.name == 'nt':
        magic = F'{magic}-win64'
    requirements.append(magic)

    extras = get_setup_extras(requirements)
    config = get_setup_common()

    config.update(
        name=refinery.__distribution__,
        packages=setuptools.find_packages(include=('refinery*',)),
        install_requires=requirements,
        extras_require=extras,
        include_package_data=True,
        entry_points={'console_scripts': console_scripts},
        package_data={'refinery': ['__init__.pkl']},
        cmdclass={'deploy': DeployCommand},
    )

    return config


if __name__ == '__main__':
    setuptools.setup(**get_config())
