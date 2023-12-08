#!/usr/bin/env python3
import logging

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))
logging.getLogger("CustomSimProcedureWindows").setLevel("INFO")
