#!/usr/bin/env python3
# -*-coding:UTF-8 -*
"""
The CVE Module
======================

This module is consuming the Redis-list created by the Categ module.

It apply CVE regexes on paste content and warn if a reference to a CVE is spotted.

"""

import time
import re
from pubsublogger import publisher
from packages import Paste
from Helper import Process


def search_cve(message):
    filepath, count = message.split()
    paste = Paste.Paste(filepath)
    content = paste.get_p_content()
    # regex to find CVE
    reg_cve = re.compile(r'(CVE-)[1-2]\d{1,4}-\d{1,5}')
    if results := set(reg_cve.findall(content)):
        print(f'{paste.p_name} contains CVEs')
        publisher.warning(f'{paste.p_name} contains CVEs')

        msg = f'infoleak:automatic-detection="cve";{filepath}'
        p.populate_set_out(msg, 'Tags')
        #Send to duplicate
        p.populate_set_out(filepath, 'Duplicate')

if __name__ == '__main__':
    # If you wish to use an other port of channel, do not forget to run a subscriber accordingly (see launch_logs.sh)
    # Port of the redis instance used by pubsublogger
    publisher.port = 6380
    # Script is the default channel used for the modules.
    publisher.channel = 'Script'

    # Section name in bin/packages/modules.cfg
    config_section = 'Cve'

    # Setup the I/O queues
    p = Process(config_section)

    # Sent to the logging a description of the module
    publisher.info("Run CVE module")

    # Endless loop getting messages from the input queue
    while True:
        # Get one message from the input queue
        message = p.get_from_set()
        if message is None:
            publisher.debug(f"{config_section} queue is empty, waiting")
            time.sleep(1)
            continue

        # Do something with the message from the queue
        search_cve(message)
