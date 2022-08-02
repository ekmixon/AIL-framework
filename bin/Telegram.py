#!/usr/bin/env python3
# -*-coding:UTF-8 -*
"""
Tools Module
============================

Search tools outpout

"""

from Helper import Process
from pubsublogger import publisher

import os
import re
import sys
import time
import redis
import signal

from urllib.parse import urlparse

sys.path.append(os.path.join(os.environ['AIL_BIN'], 'packages'))
import Item

sys.path.append(os.path.join(os.environ['AIL_BIN'], 'lib'))
import telegram

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException

signal.signal(signal.SIGALRM, timeout_handler)

# https://github.com/LonamiWebs/Telethon/wiki/Special-links
regex_telegram_link = r'(telegram\.me|t\.me|telegram\.dog|telesco\.pe)/([^\.\",\s]+)'
regex_tg_link = re.compile(r'tg://.+')

regex_username = re.compile(r'[0-9a-zA-z_]+')
regex_join_hash = re.compile(r'[0-9a-zA-z-]+')

max_execution_time = 60

def extract_data_from_telegram_url(item_id, item_date, base_url, url_path):
    invite_code_found = False

    #url = urlparse(url_path)
    url_path = url_path.split('/')
    # username len > 5, a-z A-Z _
    if len(url_path) == 1:
        username = url_path[0].lower()
        if username := regex_username.search(username):
            username = username[0].replace('\\', '')
            if len(username) > 5:
                print(f'username: {username}')
                telegram.save_item_correlation(username, item_id, item_date)
    elif url_path[0] == 'joinchat':
        if invite_hash := regex_join_hash.search(url_path[1]):
            invite_hash = invite_hash[0]
            telegram.save_telegram_invite_hash(invite_hash, item_id)
            print(f'invite code: {invite_hash}')
            invite_code_found = True
    return invite_code_found


# # TODO:
#   Add openmessafe
#   Add passport ?
#   Add confirmphone
#   Add user
def extract_data_from_tg_url(item_id, item_date, tg_link):
    invite_code_found = False

    url = urlparse(tg_link)
    # username len > 5, a-z A-Z _
    if url.netloc == 'resolve' and len(url.query) > 7:
        if url.query[:7] == 'domain=':
            # remove domain=
            username = url.query[7:]
            if username := regex_username.search(username):
                username = username[0].replace('\\', '')
                if len(username) > 5:
                    print(f'username: {username}')
                    telegram.save_item_correlation(username, item_id, item_date)
    elif url.netloc == 'join' and len(url.query) > 7:
        if url.query[:7] == 'invite=':
            invite_hash = url.query[7:]
            if invite_hash := regex_join_hash.search(invite_hash):
                invite_hash = invite_hash[0]
                telegram.save_telegram_invite_hash(invite_hash, item_id)
                print(f'invite code: {invite_hash}')
                invite_code_found = True

    elif url.netloc == 'login' and len(url.query) > 5:
        login_code = url.query[5:]
        print('login code: {}').format(login_code)

    else:
        print(url)

    return invite_code_found

def search_telegram(item_id, item_date, item_content):
    # telegram links
    signal.alarm(max_execution_time)
    try:
        telegram_links = re.findall(regex_telegram_link, item_content)
    except TimeoutException:
        telegram_links = []
        p.incr_module_timeout_statistic() # add encoder type
        print ("{0} processing timeout".format(item_id))
    else:
        signal.alarm(0)

    invite_code_found = False

    for telegram_link in telegram_links:
        res = extract_data_from_telegram_url(item_id, item_date, telegram_link[0], telegram_link[1])
        if res:
            invite_code_found = True

    # tg links
    signal.alarm(max_execution_time)
    try:
        tg_links = re.findall(regex_tg_link, item_content)
    except TimeoutException:
        tg_links = []
        p.incr_module_timeout_statistic() # add encoder type
        print ("{0} processing timeout".format(item_id))
    else:
        signal.alarm(0)

    for tg_link in tg_links:
        res = extract_data_from_tg_url(item_id, item_date, tg_link)
        if res:
            invite_code_found = True

    if invite_code_found:
        #tags
        msg = f'infoleak:automatic-detection="telegram-invite-hash";{item_id}'
        p.populate_set_out(msg, 'Tags')


if __name__ == "__main__":
    publisher.port = 6380
    publisher.channel = "Script"

    config_section = 'Telegram'
    # # TODO: add duplicate

    # Setup the I/O queues
    p = Process(config_section)

    # Sent to the logging a description of the module
    publisher.info("Run Telegram module ")

    # Endless loop getting messages from the input queue
    while True:
        # Get one message from the input queue
        item_id = p.get_from_set()
        if item_id is None:
            publisher.debug(f"{config_section} queue is empty, waiting")
            time.sleep(1)
            continue

        # Do something with the message from the queue
        item_content = Item.get_item_content(item_id)
        item_date = Item.get_item_date(item_id)
        search_telegram(item_id, item_date, item_content)
