import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from  KVMInterface import KVMInterface
import sys
import time

def main() -> int:
    """Echo the input arguments to standard output"""
    # python3 main.py win7
    filename = sys.argv[1]
    kvm = KVMInterface(filename, filename+"_file", config_vol="config/vol.xml", config_pool="config/pool.xml",
                       config="config/win7.xml", create_vm=False, image="/var/lib/libvirt/images/en_windows_7_ultimate_x64_dvd.iso")
    kvm.start_vm()
    time.sleep(10)
    kvm.stop_vm()
    return 0

if __name__ == '__main__':
    sys.exit(main())  # next section explains the use of sys.exit
