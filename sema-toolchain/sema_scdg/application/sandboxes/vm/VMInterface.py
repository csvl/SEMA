import libvirt # VMs manager
import sys

class VMInterface:
    def __init__(self,name: str) -> None:
        self.name = name
        pass

    def create_vm(self):
        pass

    def start_vm(self):
        pass

    def stop_vm(self):
        pass

    def get_vm_infos(self):
        pass

    def save_vm(self):
        pass

    def pause_vm(self):
        pass

    def resume_vm(self):
        pass
