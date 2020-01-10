from setuptools import setup

setup(
    name = 'ids_rule_parser',
    version = '0.1.0',
    packages = ['ids_rule_parser'],
    entry_points = {
        'console_scripts': [
            'ids_rule_parser = ids_rule_parser.__main__:main'
        ]
    }
)
