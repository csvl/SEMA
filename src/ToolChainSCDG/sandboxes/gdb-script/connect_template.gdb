# http://sourceware.org/gdb/wiki/FAQ: to disable the
# "---Type <return> to continue, or q <return> to quit---"
# in batch mode:

target extended-remote :ip:::port:

remote put :input: :output:

set remote exec-file :output:

r