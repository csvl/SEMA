# TODO

* set fixed version of submodule

* Benchmarking module/Response quality

* Enable automatic connection to VM (netplwiz)

* claripy redo like before (opti)

    * uninstall claripy by angr take modif version of CH

* Binpacking module

    1. Detect if binary is packed or not => OK
     
    2. Concolic execution until we reach the unpacked state

    3. Get the address to jump for classical search, then Sigmion angr

    4. start normal analysis

* Testing

    * + de pre/post pour bien faire les tests

    * unittest

    * toy examples

* TODO: packed the project in binaries

* TODO Add gridsearch

* TODO multhread version +++ need to reduce memory used

* TODO check heap config WARNING | 2022-04-01 13:46:06,112 | angr.state_plugins.heap.heap_base | Allocation request of 4294967264 bytes exceeded maximum of 128 bytes; allocating 4294967264 bytes

Normal command: 
python3 ToolChainSCDG.py --method DFS --verbose databases/malware-inputs/Sample_paper/nitol/00b2f45c7befbced2efaeb92a725bb3d
python3 ToolChainSCDG.py --method DFS --packed --verbose /malware-linux/mirai/27802001c9df792dc8e5741565d78188afbefc286076681dbdf6386863c7355c.elf


non packed:
python3 ToolChainSCDG.py --method DFS --verbose databases/malware-inputs/Sample_paper/lamer/00db7b5599813fca3116dc6f58372d61
RedLineStealer/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df
gandcrab/011c6e496c387c0c79dc06be853e19df
nitol/a0064b700bc765a90cf6bc906925280e

packed:
python3 ToolChainSCDG.py --method DFS --verbose databases/upx-dataset/upx-malware-inputs/files/00db7b5599813fca3116dc6f58372d61
databases/upx-dataset/upx-malware-inputs/files/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df
databases/upx-dataset/upx-malware-inputs/files/011c6e496c387c0c79dc06be853e19df
databases/upx-dataset/upx-malware-inputs/files/a0064b700bc765a90cf6bc906925280e

python3 ToolChainSCDG.py --method DFS --verbose --packed /home/crochetch/Documents/toolchain_malware_analysis/src/submodules/binaries/tests/x86_64/packed_elf64

python3 ToolChainSCDG.py --method DFS --verbose /home/crochetch/Documents/toolchain_malware_analysis/src/submodules/binaries/tests/x86_64/not_packed_elf64


python3 ToolChainSCDG.py --method DFS --verbose /home/crochetch/Documents/toolchain_malware_analysis/src/databases/upx-dataset/upx-malware-inputs/files/unpacked_0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df