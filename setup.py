from setuptools import setup

setup(
    name = 'idsparser',
    version = '0.1.0',
    packages = ['idsparser'],
    entry_points = {
        'console_scripts': [
            'idsparser = idsparser.__main__:main'
        ]
    }
)
