import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from angr import SimProcedure
import logging
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

class SetLocaleInfoW(SimProcedure):
    def run(self, Locale, LCType, lpLCData, cchData):
        if not self.state.has_plugin("plugin_locale_info"):
            lw.warning("Procedure SetLocaleInfoW is using the plugin plugin_locale_info which is not activated")
        # In this simprocedure, you would implement the logic for setting locale information for the specified locale and lctype.
        if self.state.has_plugin("plugin_locale_info"):
            self.state.memory.store(self.state.plugin_locale_info.locale_info_block, lpLCData)

            self.state.plugin_locale_info.locale_info[self.state.solver.eval(Locale)] = (LCType, lpLCData, cchData)
            # You could then return the appropriate result based on whether the operation was successful or not.
        return 1  # Indicating success
