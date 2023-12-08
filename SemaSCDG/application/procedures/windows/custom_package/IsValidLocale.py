import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class IsValidLocale(angr.SimProcedure):
    def run(
        self,
        Locale,
        dwFlags
    ):
        return 0x1 # TODO check if == LOCALE_CUSTOM_DEFAULT etc
