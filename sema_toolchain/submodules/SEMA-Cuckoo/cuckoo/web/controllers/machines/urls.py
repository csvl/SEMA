import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url

from cuckoo.web.controllers.machines.api import MachinesApi

urlpatterns = [
    url(r"^api/list/$", MachinesApi.list),
    url(r"^api/view/(?P<name>\w+)/$", MachinesApi.view),
]
