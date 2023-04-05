import os
import time
import sys 

while True:
    try:
        os.system("gdbserver --multi --remote-debug --dubug $IP$:9876")
    except Exception as e:
        print(e)