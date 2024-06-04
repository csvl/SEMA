import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import json
import os

class DDLLoader:
    def __init__(self):
        self.calls_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "calls")
        )

    def read_call_file(self, filename, dirname):
        with open(os.path.join(dirname, filename), "r") as fp:
            return json.load(fp)

    def load(self, project,force=False,dll=None):
        if project.loader.main_object.os == "windows":
            return {k: v for k, v in self.load_gen(project,force,dll)}
        else:
            return {}  # TODO: throw error ?

    def load_more(self, new_lib, actual_table):
        try:
            lib = new_lib.lower() + ".json"
            test = self.read_call_file(lib, self.calls_dir)
            actual_table[new_lib.lower()] = test
            # print("Success to load_more")
        except:
            # print("Fail to load_more")
            pass

    def load_gen(self, project,force=False,dll=None):
        loaded = []
        reqName = project.loader.requested_names if not dll else dll
        for f in os.listdir(os.path.join(self.calls_dir)):
            dllname = f.replace(".json", "")
            if dllname in reqName or force:
                loaded.append(f)
                yield dllname, self.read_call_file(f, self.calls_dir)
