import angr
import logging
import re 

from .PluginEnvVar import *
from .PluginLocaleInfo import *
from .PluginRegistery import *
from .PluginHooks import *
from .PluginWideChar import *
from .PluginResources import *
from .PluginEvasion import *

class PluginThread(angr.SimStatePlugin):
    def __init__(self, sema_scdg, exp_dir, proj, nameFileShort, options, args):
        super(PluginThread, self).__init__()
        self.last_error = 0
        self.registery_block = 0
        self.registery = {}
        self.stop_flag = False
        self.log = logging.getLogger("PluginThread")
        self.sema_scdg = sema_scdg
        self.exp_dir = exp_dir
        self.proj = proj
        self.nameFileShort = nameFileShort
        self.options = options
        self.args = args
        
    def post_run_thread(self, simgr):
        self.log.info("Run post-thread analysis")
        done = []
        for state in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            if len(state.globals["create_thread_address"]) > 0:
                self.log.info(state.globals["create_thread_address"])
                for elem in state.globals["create_thread_address"]:
                    if elem not in done:
                        self.log.info(state.globals["create_thread_address"])
                        self.log.info(elem)
                        self.run_thread(None,state=elem["new_state"])
                        done.append(elem)
                            
    def pre_run_thread(self, cont, inputs):
        thread_func = ["CreateThread","CreateRemoteThread"]
        main_obj = self.state.proj.main_object
        for thread_f in thread_func:
            if thread_f in main_obj.imports:
                self.log.info("CreateThread - Import addresses")
                self.log.info(main_obj.imports[thread_f])
                self.log.info("CreateThread - Relative address")
                self.log.info(0x400000 + main_obj.imports[thread_f].relative_addr)
                createThreadAddr = int.to_bytes(0x400000 + main_obj.imports[thread_f].relative_addr,length=4, byteorder='little', signed=True)
            
                pe_header       = int.from_bytes(cont[0x3c:0x40],"little")
                size_of_headers = int.from_bytes(cont[pe_header+0x54:pe_header+0x54+4],"little")
                base_of_code    = int.from_bytes(cont[pe_header+0x2c:pe_header+0x2c+4],"little")
                image_base      = int.from_bytes(cont[pe_header+0x34:pe_header+0x34+4],"little")
                total           = base_of_code+image_base-size_of_headers
                jmp_create_thread = [m.start()+total for m in re.finditer(b"\xff\x25"+createThreadAddr,cont)]
                jmp_create_thread.reverse()
                call_create_thred = [m.start()+total for m in re.finditer(b"\xff\x15"+createThreadAddr,cont)]
                call_create_thred.reverse()
                    
                self.log.info("CreateThread - JMP addresses")
                self.log.info(jmp_create_thread)
                self.log.info("CreateThread - CALL addresses")
                self.log.info(call_create_thred) 
                
                addresses = [0x400000 + main_obj.imports[thread_f].relative_addr] + jmp_create_thread + call_create_thred
                    
                # some error, see penv-fix/angr
                # TODO serena try both
                proj_static = angr.Project(
                        inputs,
                        use_sim_procedures=True,
                        load_options={
                            "auto_load_libs": True
                        },  # ,load_options={"auto_load_libs":False}
                        support_selfmodifying_code=True,
                        # arch="",
                        default_analysis_mode="static",
                )
                cfg =  proj_static.analyses.CFG(show_progressbar=True,
                                            detect_tail_calls=True,
                                            force_complete_scan=True,
                                            force_smart_scan=False,
                                            force_segment=True,
                                            function_prologues=True,
                                            use_patches=False,
                                            data_references=True,
                                            normalize=True,
                                            function_starts=addresses,
                                            #context_sensitivity_level=2, # base 0
                                            cross_references=False, # can bug
                                            #sp_tracking_track_memory=True, # not x86
                                            skip_unmapped_addrs=False,
                                            exclude_sparse_regions=False,
                                            skip_specific_regions=False,
                                            indirect_jump_target_limit=100000*1000,
                                            nodecode_window_size=512*2,
                                            nodecode_threshold=0.3*2,
                                            nodecode_step=16483*2)
                    
                    # self.log.info("Plot CFG")
                    # plot_cfg(cfg, "cfg", asminst=True, 
                    #          remove_imports=True, debug_info=True,
                    #          remove_path_terminator=True)  
                    
                    
                self.log.info("Proceeding JMP threads:")
                if len(jmp_create_thread) > 0:
                    for jmp in jmp_create_thread:
                        self.log.info(hex(jmp))    
                        self.manage_thread(cfg, jmp) # proj_static
                self.log.info("Proceeding CALL threads:")      
                if len(call_create_thred) > 0:
                    for call in call_create_thred:
                        self.log.info(hex(call))      
                        self.manage_thread(cfg, call)
                            
                print('end')
                #exit()
        
    def manage_thread(self, cfg, jmp):
        if jmp not in cfg.kb.functions:
            self.log.info("jmp NOT IN cfg.kb.functions")    
            node = cfg.get_any_node(jmp)
            if node is None:
                self.log.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", jmp)
                return
            in_edges = cfg.graph.in_edges(node, data=True)
            call_sites_by_function: Dict['Function',List[Tuple[int,int]]] = defaultdict(list)
            for src, _, data in in_edges:
                edge_type = data.get('jumpkind', 'Ijk_Call')
                if edge_type != 'Ijk_Call':
                    continue
                if not cfg.kb.functions.contains_addr(src.function_address):
                    continue
                caller = cfg.kb.functions[src.function_address]
                cc_analysis = self.proj.analyses.CallingConvention(caller, cfg=cfg, analyze_callsites=True)
                caller = cc_analysis.kb.functions[src.function_address]
                if caller.is_simprocedure:
                                # do not analyze SimProcedures
                    continue
                call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))
            call_sites_by_function_list = list(call_sites_by_function.items())[:3]
            for caller, call_sites in call_sites_by_function_list:
                print(call_sites)
                for site in call_sites:
                    self.run_thread(site)
                    
                for b in caller.block_addrs:
                    print(b)
                    self.run_thread([b])
            self.run_thread([jmp])
            return
        
        self.log.info("jmp IN cfg.kb.functions")    
        f = cfg.kb.functions[jmp]
        f.calling_convention = SimCCStdcall(self.proj.arch)
       
        #f.calling_convention = SimCCStdcall(proj.arch)
        self.log.info(f.name)
        #blank_state = proj.factory.blank_state()
                    
        prop = self.proj.analyses.Propagator(func=f, base_state=self.state)
        # Collect all the refs
        self.proj.analyses.XRefs(func=f, replacements=prop.replacements)
        #thread_func = cfg.kb.functions[jmp]
        self.log.info("Thread func:")
        self.log.info(f)
        _ = self.proj.analyses.VariableRecoveryFast(f) # TODO usefull ?
        cc_analysis = self.proj.analyses.CallingConvention(f, cfg=cfg, analyze_callsites=True)
        self.log.info("Thread args:")
        self.log.info(cc_analysis.prototype.args)  
        node = cfg.get_any_node(jmp)
        if node is None:
            self.log.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", jmp)
        in_edges = cfg.graph.in_edges(node, data=True)
        call_sites_by_function: Dict['Function',List[Tuple[int,int]]] = defaultdict(list)
        for src, _, data in in_edges:
            print(src)
            print(data)
            edge_type = data.get('jumpkind', 'Ijk_Call')
            print(edge_type)
            print("")
            # if edge_type != 'Ijk_Call':
            #     continue
            # if not cc_analysis.kb.functions.contains_addr(src.function_address):
            #     continue
            caller = cc_analysis.kb.functions[src.function_address]
            # if caller.is_simprocedure:
            #                 # do not analyze SimProcedures
            #     continue
            call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))
        call_sites_by_function_list = list(call_sites_by_function.items())[:3]
        self.log.info("Call sites list:")
        self.log.info(call_sites_by_function_list)
        for caller, call_sites in call_sites_by_function_list:
            self.log.info("Call sites")
            self.log.info(call_sites)
            for site in call_sites:
                self.run_thread(site)
        self.log.info("Blocks sites list:")
        self.log.info(f.block_addrs)
        for b in f.block_addrs:
            self.log.info("Blocks address")
            self.log.info(b)
            self.run_thread([b])

    
    def run_thread(self, site, state=None):
        #exit()
        if not state: # pre thread
            tstate = self.proj.factory.entry_state(addr=site[0], add_options=self.options)
        else:         # post thread
            tstate = state
            #tstate.globals["id"] = tstate.globals["id"] + 1
        
        if self.args:
            nthread = None if self.args.sthread <= 1 else self.args.sthread
        else:
            nthread = None
            
        tsimgr = self.proj.factory.simulation_manager(tstate,threads=nthread)
        tsimgr._techniques = []  
        
        if not state:
            tstate.options.discard("LAZY_SOLVES")
            tstate.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size =int(64*4096*10*10*10*4*2)))
                        
            tstate.register_plugin("plugin_env_var", PluginEnvVar()) 
            tstate.plugin_env_var.setup_plugin(self.expl_method)
            
            tstate.register_plugin("plugin_locale_info", PluginLocaleInfo()) 
            tstate.plugin_locale_info.setup_plugin()
        
            tstate.register_plugin("plugin_resources", PluginResources())
            tstate.plugin_resources.setup_plugin()
            
            tstate.register_plugin("plugin_widechar", PluginWideChar())
            
            tstate.register_plugin("plugin_registery", PluginRegistery())
            tstate.plugin_registery.setup_plugin()
        
            # Create ProcessHeap struct and set heapflages to 0
            tib_addr = tstate.regs.fs.concat(tstate.solver.BVV(0, 16))
            peb_addr = tstate.mem[tib_addr + 0x30].dword.resolved
            ProcessHeap = peb_addr + 0x500
            tstate.mem[peb_addr + 0x18].dword = ProcessHeap
            tstate.mem[ProcessHeap+0xc].dword = 0x0  #heapflags windowsvistaorgreater
            tstate.mem[ProcessHeap+0x40].dword = 0x0 #heapflags else
            
            self.sema_scdg.hooks.hook(tstate,self.proj)
                
            tstate.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
            tstate.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
            tstate.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
            tstate.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
            
            tsimgr.stashes["pause"] = []
            tsimgr.stashes["new_addr"] = []
            tsimgr.stashes["ExcessLoop"] = []
            tsimgr.stashes["ExcessStep"] = []          
            tsimgr.stashes["deadbeef"] = []
            tsimgr.stashes["lost"] = []
            
        self.sema_scdg.setup_stash(tsimgr)
        
        tsimgr.active[0].globals["is_thread"] = True
                            
        exploration_tech_thread = self.sema_scdg.get_exploration_tech(self.args, self.exp_dir, self.nameFileShort, tsimgr)
        
        tsimgr.use_technique(exploration_tech_thread)

        self.log.info("\n------------------------------\nStart -State of simulation manager :\n "
                     + str(tsimgr)
                    + "\n------------------------------")
                                
        tsimgr.run()
        self.sema_scdg.build_scdg_fin(self.exp_dir, self.nameFileShort, self.state.proj.loader.main_object, tstate, tsimgr)
        self.sema_scdg.build_ioc(self.exp_dir, self.nameFileShort, self.state.proj.loader.main_object, tstate, tsimgr)
        

    # @angr.SimStatePlugin.memo
    # def copy(self, memo):
    #     p = PluginThread(self.sema_scdg, self.exp_dir, self.proj, self.nameFileShort, self.options, self.args)
    #     p.last_error = self.last_error
    #     p.registery_block = self.registery_block
    #     p.registery = self.registery.copy()
    #     p.stop_flag = self.stop_flag
    #     return p
