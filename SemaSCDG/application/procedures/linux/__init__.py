#!/usr/bin/env python3
import logging
import os

lw = logging.getLogger("CustomSimProcedureLinux")
lw.setLevel(os.environ["LOG_LEVEL"])
