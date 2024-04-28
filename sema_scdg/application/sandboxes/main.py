from  vm.kvm.KVMInterface import KVMInterface
from CuckooInterface import CuckooInterface
import sys
import time
def main() -> int:
    """Echo the input arguments to standard output"""
    # python3 main.py win7 /home/crochetch/Documents/toolchain_malware_analysis/src/res/malware-inputs/Sample_paper/lamer/00b6b682fe26b3b0dac16f60869dd753
    # python3 main.py cuckoo_ubuntu18.04 /home/crochetch/Documents/toolchain_malware_analysis/src/res/malware-inputs/Sample_paper/lamer/00b6b682fe26b3b0dac16f60869dd753
    filename = sys.argv[1]
    analysis = sys.argv[2]
    cuckoo = CuckooInterface(name=filename, ossys="linux", guestos="linux", create_vm=False)
    cuckoo.start_sandbox()
    cuckoo.load_analysis(analysis)
    #cuckoo.start_analysis()
    #cuckoo.stop_sandbox()

    return 0

if __name__ == '__main__':
    sys.exit(main())  # next section explains the use of sys.exit
