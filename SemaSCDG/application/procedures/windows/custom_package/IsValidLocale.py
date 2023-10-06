import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class IsValidLocale(angr.SimProcedure):
    def run(
        self,
        Locale,
        dwFlags
    ):
        return 0x1 # TODO check if == LOCALE_CUSTOM_DEFAULT etc
