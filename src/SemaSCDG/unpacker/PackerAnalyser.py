# From unicorn

import threading
from unipacker_ucl.core import Sample, SimpleClient, UnpackerEngine

class PackerAnalyser:
    def __init__(self, file,unpacker_heartbeat):
        self.sample = Sample(file)
        self.event = threading.Event()
        self.client = SimpleClient(self.event)
        unpacked_file_path = file.replace(file,"unpacked_"+file)
        self.engine = UnpackerEngine(self.sample, unpacked_file_path)
        self.engine.register_client(self.client)
        self.unpacker_heartbeat = unpacker_heartbeat
        self.unpacker_heartbeat.start()
        self.threading.Thread(target=self.engine.emu).start()
        self.event.wait()
        self.unpacker_heartbeat.stop()
        self.engine.stop()