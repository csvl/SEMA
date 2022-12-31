import json
import os


class LinuxTableLoader:
    def __init__(self, filename=""):
        self.syscall_libraries = {
            "windows": {"AMD64": "", "X86": ""},
            "linux": {
                "AMD64": "syscalls_linux_64.json",
                "X86": "syscalls_linux_32.json",
            },
        }
        self.filename = filename
        self.calls_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "calls")
        )

    def read_file(self, filename):
        f = open(self.calls_dir + "/" +  filename, "r")
        return json.load(f)

    def load_table(self, project):
        os = project.loader.main_object.os
        if os in ["UNIX - System V", "UNIX - Linux"]:
            to_load = self.syscall_libraries["linux"]
        else:
            return {}
        arch_name = project.loader.main_object.arch.name
        if arch_name in to_load.keys():
            syscall_lib = to_load[arch_name]
            return self.read_file(syscall_lib)
        else:
            print("CPU architecture not supported") # TODO only stop build_scdg
            exit(0)
