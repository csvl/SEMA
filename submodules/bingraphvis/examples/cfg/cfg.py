#! /usr/bin/env python

from bingraphvis import DotOutput
from bingraphvis.angr import *
from bingraphvis.openreil import *
from bingraphvis.angr.x86 import *

samples_dir = "../../samples/cfg/"

import angr

def angr_cfg(sample):
    proj = angr.Project(samples_dir + sample, load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    addr = main.rebased_addr
    start_state = proj.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = proj.analyses.CFGFast(fail_fast=True, function_starts=[addr], base_state=start_state, normalize=False)

    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=True, vexinst=False)
    vis.set_output(DotOutput(sample + '_angr_asm', format="png"))
    vis.process(cfg.graph)

    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=False, vexinst=True)
    vis.set_output(DotOutput(sample + '_angr_vex', format="png"))
    vis.process(cfg.graph)

from pyopenreil.REIL import *
from pyopenreil.utils import bin_BFD

def openreil_cfg(sample):
    reader = bin_BFD.Reader(samples_dir + sample)
    addr = None
    for k,v in reader.bfd.symbols.items():
        if v.name == 'main':
            addr = k

    tr = CodeStorageTranslator(reader)
    cfg = CFGraphBuilder(tr).traverse(addr)

    vis = OpenreilVisFactory().default_cfg_pipeline(asminst=True, reilinst=False)
    vis.set_output(DotOutput(sample + '_openreil_asm', format="png"))
    vis.process(cfg)

    vis = OpenreilVisFactory().default_cfg_pipeline(asminst=False, reilinst=True)
    vis.set_output(DotOutput(sample + '_openreil_reil', format="png"))
    vis.process(cfg)

    #cfg.to_dot_file('openreil_' + sample + ".raw")

if __name__ == "__main__":
    samples = ["cfg_0"]
    for sample in samples:
        angr_cfg(sample)
        openreil_cfg(sample)
