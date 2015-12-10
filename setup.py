from setuptools import setup

setup(
    name="OpenPGPyCard",
    py_modules=["OpenPGPyCard"],
    description="OpenPGPyCard is a simple OpenPGP card driver",
    version=0.1,
    author='Ivan Markin',
    author_email='0x8F5C9F5B',
    license='GPLv3',
    keywords=['openpgp','card','smartcard'],
    install_requires=[
        'pycrypto>=2.6.1',
        'pyscard>=1.7.0',
        'future>=0.14.0'
        ],
)
