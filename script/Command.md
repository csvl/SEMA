
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

python3 ToolChainSCDG.py --method DFS --verbose --packed /home/crochetch/Documents/SEMA-ToolChain/src/submodules/binaries/tests/x86_64/packed_elf64

python3 ToolChainSCDG.py --method DFS --verbose /home/crochetch/Documents/SEMA-ToolChain/src/submodules/binaries/tests/x86_64/not_packed_elf64


python3 ToolChainSCDG.py --method DFS --verbose /home/crochetch/Documents/SEMA-ToolChain/src/databases/upx-dataset/upx-malware-inputs/files/unpacked_0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df