from classifier import *

clf = Gspan_classifier('test_clf7/')
clf.train('Signatures_merge_call_CBFS/')
ret = clf.evaluate()
print(ret)
clf.get_stat_classifier()

######################## flemme
perf ="Precision obtained : 0.6752136752136753 Recall obtained : 0.6752136752136753"

perf_cdfs_nol_comparg = "Precision obtained : 0.6026823480228212 Recall obtained : 0.5955882352941176 Fscore obtained : 0.5991142920461497"
perf_cdfs_nol ="Precision obtained : 0.6712698412698413 Recall obtained : 0.6538461538461539 Fscore obtained : 0.6624434472527574"

