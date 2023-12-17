#!/usr/bin/env python3
import logging
import os

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel(os.environ["LOG_LEVEL"])
