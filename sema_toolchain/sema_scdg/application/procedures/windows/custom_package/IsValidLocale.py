import os
import sys


import logging
import angr
import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class IsValidLocale(angr.SimProcedure):
    def run(
        self,
        Locale,
        dwFlags
    ):
        return 0x1 # TODO check if == LOCALE_CUSTOM_DEFAULT etc
