from setuptools import setup, find_packages
import codecs
import os
import platform


# Get the long description from the README file
here = os.path.abspath(os.path.dirname(__file__))
try:
  with codecs.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
      long_description = f.read()
except:
  # This happens when running tests
  long_description = None

# TODO test if good

setup(name='ucl_tc_malware_analysis',
      version='0.1',
      description='ToolChain for Malware Analysis',
      long_description=long_description,
      url='https://forge.uclouvain.be/crochetch/toolchain_malware_analysis.git',
      author='A-Team from UCLouvain',
      author_email='nomail@uclouvain.com',
      license='MIT', # lol we dont know
      packages=find_packages(),
      setup_requires=['wheel'],
      install_requires=[
          'pymongo', # malwexp
          'pyzipper', 
          'click',
          'requests',
          'graphviz',
          'monkeyhex',
          'angr==8.20.7.27', # 8.20.7.27 for symbion (not working after)
          'researchpy',
          'hypothesis',
          'seaborn',
          'scipy',
          'scikit-learn', #'sklearn',
          'grakel',
          'claripy',
          'protobuf==3.20.*',
          "unix",
          'kvm',
          'libvirt-python',
          'unipacker',
          "minidump==0.0.10"
      ],
      zip_safe=False)