import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class IsValidLocale(angr.SimProcedure):
    def run(
        self,
        Locale,
        dwFlags
    ):
        return 0x1 # TODO check if == LOCALE_CUSTOM_DEFAULT etc
