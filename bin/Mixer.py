#!/usr/bin/env python3
# -*-coding:UTF-8 -*
"""
The Mixer Module
================

This module is consuming the Redis-list created by the ZMQ_Feed_Q Module.

This module take all the feeds provided in the config.
Depending on the configuration, this module will process the feed as follow:
    operation_mode 1: "Avoid any duplicate from any sources"
        - The module maintain a list of content for each paste
            - If the content is new, process it
            - Else, do not process it but keep track for statistics on duplicate

    operation_mode 2: "Keep duplicate coming from different sources"
        - The module maintain a list of name given to the paste by the feeder
            - If the name has not yet been seen, process it
            - Elseif, the saved content associated with the paste is not the same, process it
            - Else, do not process it but keep track for statistics on duplicate

    operation_mode 3: "Don't look if duplicated content"
        - SImply do not bother to check if it is a duplicate
        - Simply do not bother to check if it is a duplicate

Note that the hash of the content is defined as the sha1(gzip64encoded).

Every data coming from a named feed can be sent to a pre-processing module before going to the global module.
The mapping can be done via the variable FEED_QUEUE_MAPPING

"""

import os
import sys

import base64
import hashlib
import time
from pubsublogger import publisher
import redis

from Helper import Process

sys.path.append(os.path.join(os.environ['AIL_BIN'], 'lib/'))
import ConfigLoader


# CONFIG #
refresh_time = 30
FEED_QUEUE_MAPPING = { "feeder2": "preProcess1" } # Map a feeder name to a pre-processing module

if __name__ == '__main__':
    publisher.port = 6380
    publisher.channel = 'Script'

    config_section = 'Mixer'

    p = Process(config_section)

    config_loader = ConfigLoader.ConfigLoader()

    # REDIS #
    server = config_loader.get_redis_conn("Redis_Mixer_Cache")
    server_cache = config_loader.get_redis_conn("Redis_Log_submit")

    # LOGGING #
    publisher.info("Feed Script started to receive & publish.")

    # OTHER CONFIG #
    operation_mode = config_loader.get_config_int("Module_Mixer", "operation_mode")
    ttl_key = config_loader.get_config_int("Module_Mixer", "ttl_duplicate")
    default_unnamed_feed_name = config_loader.get_config_str("Module_Mixer", "default_unnamed_feed_name")

    PASTES_FOLDER = os.path.join(os.environ['AIL_HOME'], config_loader.get_config_str("Directories", "pastes")) + '/'
    config_loader = None

    # STATS #
    processed_paste = 0
    processed_paste_per_feeder = {}
    duplicated_paste_per_feeder = {}
    time_1 = time.time()

    print(f'Operation mode {str(operation_mode)}')

    while True:

        message = p.get_from_set()
        if message is not None:
            splitted = message.split()
            if len(splitted) == 2:
                complete_paste, gzip64encoded = splitted

                try:
                    #feeder_name = ( complete_paste.replace("archive/","") ).split("/")[0]
                    feeder_name, paste_name = complete_paste.split('>>')
                    feeder_name.replace(" ","")
                    if 'import_dir' in feeder_name:
                        feeder_name = feeder_name.split('/')[1]

                except ValueError as e:
                    feeder_name = default_unnamed_feed_name
                    paste_name = complete_paste

                # remove absolute path
                paste_name = paste_name.replace(PASTES_FOLDER, '', 1)

                # Processed paste
                processed_paste += 1
                try:
                    processed_paste_per_feeder[feeder_name] += 1
                except KeyError as e:
                    # new feeder
                    processed_paste_per_feeder[feeder_name] = 1
                    duplicated_paste_per_feeder[feeder_name] = 0


                relay_message = "{0} {1}".format(paste_name, gzip64encoded)
                #relay_message = b" ".join( [paste_name, gzip64encoded] )

                digest = hashlib.sha1(gzip64encoded.encode('utf8')).hexdigest()

                # Avoid any duplicate coming from any sources
                if operation_mode == 1:
                    if server.exists(digest): # Content already exists
                        #STATS
                        duplicated_paste_per_feeder[feeder_name] += 1
                    elif feeder_name in FEED_QUEUE_MAPPING:
                        p.populate_set_out(relay_message, FEED_QUEUE_MAPPING[feeder_name])
                    else:
                        p.populate_set_out(relay_message, 'Mixer')

                    server.sadd(digest, feeder_name)
                    server.expire(digest, ttl_key)


                elif operation_mode == 2:
                    # Filter to avoid duplicate
                    content = server.get(f'HASH_{paste_name}')
                    if content is None:
                        # New content
                        # Store in redis for filtering
                        server.set(f'HASH_{paste_name}', digest)
                        server.sadd(paste_name, feeder_name)
                        server.expire(paste_name, ttl_key)
                        server.expire(f'HASH_{paste_name}', ttl_key)

                        # populate Global OR populate another set based on the feeder_name
                        if feeder_name in FEED_QUEUE_MAPPING:
                            p.populate_set_out(relay_message, FEED_QUEUE_MAPPING[feeder_name])
                        else:
                            p.populate_set_out(relay_message, 'Mixer')

                    else:
                        # Same paste name but different content
                        #STATS
                        duplicated_paste_per_feeder[feeder_name] += 1
                        if digest != content:
                            server.sadd(paste_name, feeder_name)
                            server.expire(paste_name, ttl_key)

                            # populate Global OR populate another set based on the feeder_name
                            if feeder_name in FEED_QUEUE_MAPPING:
                                p.populate_set_out(relay_message, FEED_QUEUE_MAPPING[feeder_name])
                            else:
                                p.populate_set_out(relay_message, 'Mixer')

                elif feeder_name in FEED_QUEUE_MAPPING:
                    p.populate_set_out(relay_message, FEED_QUEUE_MAPPING[feeder_name])
                else:
                    p.populate_set_out(relay_message, 'Mixer')


            else:
                # TODO Store the name of the empty paste inside a Redis-list.
                print("Empty Paste: not processed")
                publisher.debug("Empty Paste: {0} not processed".format(message))
        else:

            if int(time.time() - time_1) > refresh_time:
                if list_feeder := server_cache.hkeys(
                    "mixer_cache:list_feeder"
                ):
                    for feeder in list_feeder:
                        count = int(server_cache.hget("mixer_cache:list_feeder", feeder))
                        if count is None:
                            count = 0
                        processed_paste_per_feeder[feeder] = processed_paste_per_feeder.get(feeder, 0) + count
                        processed_paste = processed_paste + count
                print(processed_paste_per_feeder)
                to_print = 'Mixer; ; ; ;mixer_all All_feeders Processed {0} paste(s) in {1}sec'.format(processed_paste, refresh_time)
                print(to_print)
                publisher.info(to_print)
                processed_paste = 0

                for feeder, count in processed_paste_per_feeder.items():
                    to_print = 'Mixer; ; ; ;mixer_{0} {0} Processed {1} paste(s) in {2}sec'.format(feeder, count, refresh_time)
                    print(to_print)
                    publisher.info(to_print)
                    processed_paste_per_feeder[feeder] = 0

                for feeder, count in duplicated_paste_per_feeder.items():
                    to_print = 'Mixer; ; ; ;mixer_{0} {0} Duplicated {1} paste(s) in {2}sec'.format(feeder, count, refresh_time)
                    print(to_print)
                    publisher.info(to_print)
                    duplicated_paste_per_feeder[feeder] = 0

                time_1 = time.time()

                # delete internal feeder list
                server_cache.delete("mixer_cache:list_feeder")
            time.sleep(0.5)
            continue
