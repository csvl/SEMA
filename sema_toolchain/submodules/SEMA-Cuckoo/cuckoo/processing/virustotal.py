import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from cuckoo.common.abstracts import Processing
from cuckoo.common.config import config
from cuckoo.common.exceptions import (
    CuckooOperationalError, CuckooProcessingError
)
from cuckoo.common.virustotal import (
    VirusTotalAPI, VirusTotalResourceNotScanned
)

log = logging.getLogger(__name__)

class VirusTotal(Processing):
    """Get antivirus signatures from VirusTotal.com for various results.

    Currently obtains VirusTotal results for the target sample or URL and the
    dropped files.
    """
    order = 2

    def run(self):
        """Run VirusTotal processing
        @return: full VirusTotal report.
        """
        self.key = "virustotal"

        if not config("processing:virustotal:key"):
            raise CuckooProcessingError(
                "VirusTotal API key not configured, skipping the VirusTotal "
                "processing module."
            )

        self.vt = VirusTotalAPI()

        # Scan the original sample or URL.
        if self.task["category"] == "file":
            results = self.scan_file(self.file_path)
        elif self.task["category"] == "url":
            results = self.scan_url(self.task["target"])
        elif self.task["category"] == "baseline":
            return
        elif self.task["category"] == "service":
            return
        else:
            raise CuckooProcessingError(
                "Unsupported task category: %s" % self.task["category"]
            )

        # Scan any dropped files that have an interesting filetype.
        for row in self.results.get("dropped", []):
            if not self.should_scan_file(row["type"]):
                continue

            row["virustotal"] = self.scan_file(row["path"], summary=True)

        return results

    def scan_file(self, filepath, summary=False):
        """Retrieve VirusTotal results for a file.
        @param filepath: file path
        @param summary: if you want a summary report
        """
        if not os.path.exists(filepath):
            log.warning("Path \"%s\" could not be found for VirusTotal "
                        "lookup, skipping it", os.path.basename(filepath))
            return

        try:
            return self.vt.file_report(filepath, summary=summary)
        except VirusTotalResourceNotScanned:
            return self.vt.file_scan(filepath)
        except CuckooOperationalError as e:
            log.warning("Error fetching results from VirusTotal for "
                        "\"%s\": %s", os.path.basename(filepath), e.message)

    def scan_url(self, url, summary=False):
        """Retrieve VirusTotal results for a URL.
        @param url: URL
        @param summary: if you want a summary report
        """
        try:
            return self.vt.url_report(url, summary=summary)
        except VirusTotalResourceNotScanned:
            return self.vt.url_scan(url)
        except CuckooOperationalError as e:
            log.warning("Error fetching results from VirusTotal for "
                        "\"%s\": %s", url, e.message)

    def should_scan_file(self, filetype):
        """Determine whether a certain filetype should be scanned on
        VirusTotal. For example, we're not interested in scanning text
        files.
        @param filetype: file type
        """
        return "PE32" in filetype or "MS-DOS" in filetype
