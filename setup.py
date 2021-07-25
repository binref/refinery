#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import setuptools
import os
import re
import os.path
import sys
import toml

PREFIX = os.getenv('REFINERY_PREFIX') or ''
GITHUB = 'https://github.com/binref/refinery/'
GITRAW = 'https://raw.githubusercontent.com/binref/refinery/'

cache_path = os.path.join(os.path.dirname(__file__), 'refinery', '__init__.pkl')
if os.path.exists(cache_path):
    os.remove(cache_path)


def normalize_name(name, separator='-'):
    return separator.join([segment for segment in name.split('_')])


def main():
    import refinery.lib.loader as loader
    import refinery

    if sys.version_info < (3, 7):
        print('ERROR: Python version at least 3.7 is required.', file=sys.stderr)
        sys.exit(0xFADE)

    requirements = toml.load('pyproject.toml')['build-system']['requires']

    magic = 'python-magic'
    if os.name == 'nt':
        magic = F'{magic}-win64'
    requirements.append(magic)

    with open('README.md', 'r', encoding='UTF8') as README:
        def complete_link(match):
            link = match[1]
            if any(link.lower().endswith(xt) for xt in ('jpg', 'gif', 'png', 'svg')):
                return F'({GITRAW}master/{link})'
            else:
                return F'({GITHUB}blob/master/{link})'
        readme = README.read()
        readme = re.sub(R'(?<=\])\((?!\w+://)(.*?)\)', complete_link, readme)

    if PREFIX == '!':
        console_scripts = []
    else:
        console_scripts = [
            '{}{}={}:{}.run'.format(
                PREFIX,
                normalize_name(item.__qualname__),
                item.__module__,
                item.__qualname__
            )
            for item in loader.get_all_entry_points()
        ] + [
            'binref=refinery.explore:explorer'
        ]

    setuptools.setup(
        name=refinery.__pip_pkg__,
        version=refinery.__version__,
        author='Jesko Hüttenhain',
        description='A toolkit to transform and refine (mostly) binary data.',
        long_description=readme,
        long_description_content_type='text/markdown',
        url=GITHUB,
        python_requires='>=3.7',
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: Console',
            'License :: OSI Approved :: BSD License',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 3 :: Only',
            'Topic :: System :: Shells',
            'Topic :: Utilities'
        ],
        packages=setuptools.find_packages(
            exclude=('test*',)
        ),
        install_requires=requirements,
        entry_points={
            'console_scripts': console_scripts
        }
    )


if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(__file__))
    main()
