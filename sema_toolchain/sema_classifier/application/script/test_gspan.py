import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from classifier import *

clf = Gspan_classifier('test_clf7/')
clf.train('Signatures_merge_call_CBFS/')
ret = clf.evaluate()
print(ret)
clf.get_stat_classifier()
