# http://sourceware.org/gdb/wiki/FAQ: to disable the
# "---Type <return> to continue, or q <return> to quit---"
# in batch mode:

target extended-remote 192.168.122.254:9876

remote put /home/crochetch/Documents/toolchain_malware_analysis/src/databases/upx-dataset/upx-malware-inputs/files/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df C:\Users\user\Desktop\0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df

set remote exec-file C:\Users\user\Desktop\0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df

r