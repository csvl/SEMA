from distutils.core import setup

setup(
    name='bingraphvis',
    author='Attila Axt',
    author_email='axt@load.hu',
    license='BSD',
    platforms=['Linux'],
    version='0.4.0',
    packages=['bingraphvis', 'bingraphvis.angr', 'bingraphvis.angr.x86', 'bingraphvis.angr.arm'],
    install_requires=[
        'pydot',
        'networkx'
    ],
    long_description='Visualisation for binary analysis related graphs',
    url='https://github.com/axt/bingraphvis',
)
