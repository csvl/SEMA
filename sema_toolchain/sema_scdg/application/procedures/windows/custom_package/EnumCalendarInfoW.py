import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class EnumCalendarInfoW(angr.SimProcedure):
    def run(self, lpCalInfoEnumProc,Locale, Calendar,CalType):
        return 0x1
