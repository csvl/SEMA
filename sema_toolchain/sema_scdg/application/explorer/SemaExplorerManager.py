import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from explorer.SemaExplorerDFS import SemaExplorerDFS
from explorer.SemaExplorerCDFS import SemaExplorerCDFS
from explorer.SemaExplorerBFS import SemaExplorerBFS
from explorer.SemaExplorerCBFS import SemaExplorerCBFS

class SemaExplorerManager():

    def __init__(self):
        self.expl_tech = None

    def get_exploration_tech(self, nameFileShort, simgr, exp_dir, proj, expl_tech, scdg_graph, call_sim):
        self.expl_tech = SemaExplorerDFS(
            simgr, exp_dir, nameFileShort, scdg_graph, call_sim
        )
        if expl_tech == "CDFS":
            self.expl_tech = SemaExplorerCDFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim
            )
        elif expl_tech == "CBFS":
            self.expl_tech = SemaExplorerCBFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim
            )
        elif expl_tech == "BFS":
            self.expl_tech = SemaExplorerBFS(
                simgr, exp_dir, nameFileShort, scdg_graph, call_sim
            )

        return self.expl_tech
