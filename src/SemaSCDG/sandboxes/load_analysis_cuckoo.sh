# TODO
source /home/crochetch/Documents/toolchain_malware_analysis/penv-2.7/bin/activate
echo "cool"
echo $1
cuckoo -d --cwd /home/crochetch/Documents/toolchain_malware_analysis/src/sandboxes/.cuckoo submit $1
deactivate