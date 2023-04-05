# From unicorn

import threading
from unipacker_ucl.core import Sample, SimpleClient, UnpackerEngine


"""
Greatly inspired from unicorn
"""
class PackerAnalyser:
    def __init__(self, file,unpacker_heartbeat):
        self.sample = Sample(file)
        self.event = threading.Event()
        self.client = SimpleClient(self.event)
        
