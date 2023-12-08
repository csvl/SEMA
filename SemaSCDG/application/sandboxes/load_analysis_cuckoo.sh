# TODO
source /home/crochetch/Documents/Projects/MalwareAnalysis/SEMA-ToolChain-packing/penv-2.7/bin/activate
echo $1
cuckoo -d --cwd /home/crochetch/Documents/Projects/MalwareAnalysis/SEMA-ToolChain-packing/src/ToolChainSCDG/sandboxes/.cuckoo submit $1
deactivate