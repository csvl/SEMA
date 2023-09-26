from ..base import *
from . import *
from .x86 import *
from .arm import *

class AngrVisFactory(object):
    def __init__(self):
        pass

    def default_cfg_pipeline(self, cfg, asminst=False, vexinst=False, remove_path_terminator=True, color_edges=True, comments=True):
        project = cfg.project
        vis = Vis()
        vis.set_source(AngrCFGSource())
        if remove_path_terminator:
            vis.add_transformer(AngrRemovePathTerminator())
        vis.add_content(AngrCFGHead())
        vis.add_node_annotator(AngrColorSimprocedures())
        if asminst:
            vis.add_content(AngrAsm(project))
            if comments:
                if cfg.sort == 'fast':
                    if project.arch.name in ('X86', 'AMD64'):
                        vis.add_content_annotator(AngrX86CommentsAsm(project))
                    vis.add_content_annotator(AngrCommentsDataRef(project))
                else:
                    vis.add_content_annotator(AngrCommentsAsm(project))
        if vexinst:
            vis.add_content(AngrVex(project))
            if color_edges:
                vis.add_edge_annotator(AngrColorEdgesVex())
        elif asminst:
            if color_edges:
                if project.arch.name in ('ARM', 'ARMEL', 'ARMHF'):
                    vis.add_edge_annotator(AngrColorEdgesAsmArm())
                elif project.arch.name in ('X86', 'AMD64'):
                    vis.add_edge_annotator(AngrColorEdgesAsmX86())
                else:
                    vis.add_edge_annotator(AngrColorEdgesVex())
        return vis

    def default_func_graph_pipeline(self, project, ailinst=True, asminst=True, vexinst=False):
        vis = Vis()
        vis.set_source(AngrCommonSource())
        vis.add_content(AngrFGraphHead())
        if asminst:
            vis.add_content(AngrAsm(project))
        if vexinst:
            vis.add_content(AngrVex(project))
        if ailinst:
            vis.add_content(AngrAIL(project))
        return vis


    def default_structured_graph_pipeline(self, project, ailinst=True, asminst=True, vexinst=False):
        vis = Vis()
        vis.set_source(AngrStructuredSource())
        vis.add_content(AngrFGraphHead())
        if asminst:
            vis.add_content(AngrAsm(project))
        if vexinst:
            vis.add_content(AngrVex(project))
        if ailinst:
            vis.add_content(AngrAIL(project))
        return vis

    def default_cg_pipeline(self, kb, verbose=True):
        vis = Vis()
        vis.set_source(AngrKbCGSource())
        vis.add_content(AngrCGHead())
        if verbose:
            vis.add_content(AngrKbFunctionDetails())
        return vis

    def default_common_graph_pipeline(self, type=False):
        vis = Vis()
        vis.set_source(AngrCommonSource())
        vis.add_content(AngrCommonHead())
        if type:
            vis.add_content(AngrCommonTypeHead())
        return vis
    
    
