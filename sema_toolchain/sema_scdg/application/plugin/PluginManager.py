import os
import sys


from plugin.PluginEnvVar import PluginEnvVar
from plugin.PluginLocaleInfo import PluginLocaleInfo
from plugin.PluginRegistry import PluginRegistry
from plugin.PluginHooks import PluginHooks
from plugin.PluginWideChar import PluginWideChar
from plugin.PluginResources import PluginResources
#rom plugin.PluginEvasion import PluginEvasion
from plugin.PluginCommands import PluginCommands
from plugin.PluginIoC import PluginIoC
from plugin.PluginAtom import PluginAtom
from plugin.PluginPacking import PluginPacking
from plugin.PluginThread import PluginThread


class PluginManager():

    def __init__(self):
        self.hooks = PluginHooks()
        self.commands = PluginCommands()
        self.ioc = PluginIoC()
        self.packing = PluginPacking()

   # Load and setup plugins set to true in config file
    def load_plugin(self, state, config):
        plugin_available = config["Plugins_to_load"]
        for plugin in plugin_available:
            if config["Plugins_to_load"].getboolean(plugin):
                if plugin == "plugin_env_var" :
                    state.register_plugin(plugin, PluginEnvVar())
                    state.plugin_env_var.setup_plugin()
                elif plugin == "plugin_locale_info" :
                    state.register_plugin(plugin, PluginLocaleInfo())
                    state.plugin_locale_info.setup_plugin()
                elif plugin == "plugin_resources" :
                    state.register_plugin(plugin, PluginResources())
                    state.plugin_resources.setup_plugin()
                elif plugin == "plugin_widechar" :
                    state.register_plugin(plugin, PluginWideChar())
                elif plugin == "plugin_registry" :
                    state.register_plugin(plugin, PluginRegistry())
                    state.plugin_registry.setup_plugin()
                elif plugin == "plugin_atom" :
                    state.register_plugin(plugin, PluginAtom())
                #TODO Christophe : Check if plugin thread does the right thing (handles thread in the binary and not try to multithread angr execution)
                # elif plugin == "plugin_thread" :
                #     state.register_plugin("plugin_thread", PluginThread(self, exp_dir, proj, nameFileShort, options))

    def enable_plugin_hooks(self, content, state, proj, call_sim):
        self.hooks.initialization(content, is_64bits=proj.arch.name == "AMD64")
        self.hooks.hook(state,proj,call_sim)

    def enable_plugin_commands(self, simgr, scdg_graph, exp_dir):
        self.commands.track(simgr, scdg_graph, exp_dir)

    def enable_plugin_ioc(self, scdg_graph, exp_dir):
        self.ioc.build_ioc(scdg_graph, exp_dir)

    def get_plugin_packing(self):
        return self.packing
