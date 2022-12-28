# http://sourceware.org/gdb/wiki/FAQ: to disable the
# "---Type <return> to continue, or q <return> to quit---"
# in batch mode:
# https://sourceware.org/gdb/wiki/BuildingCrossGDBandGDBserver


#set sysroot remote:/


#file :input:

#set debug remote on

target extended-remote :ip:::port: 

remote put :input: :output:

set remote exec-file :output:

#quit
# cont