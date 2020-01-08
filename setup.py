#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''Setup Script.'''

from setuptools import setup, find_packages
from pathlib import Path


def _get_requirements():
    with open('requirements.txt') as _file:
        return _file.readlines()


def _get_long_description():
    cur_dir = Path(__file__).absolute().parent
    readme_file = cur_dir.joinpath('README').with_suffix('.md')
    with open(str(readme_file)) as _file:
        return _file.read()


setup(
    name='osa-data-model',
    version='0.0.1',
    description='Data model for OSA',
    long_description=_get_long_description(),
    author='Avishkar Gupta',
    author_email='avgupta@redhat.com',
    license='GPLv3',
    url='https://github.com/fabric8-analytics/osa-data-model',
    keywords=['CVE', 'Probable CVE'],
    python_requires='>=3.6',
    packages=find_packages(exclude=['tests', 'benchmark_data']),
    install_requires=_get_requirements(),
)
