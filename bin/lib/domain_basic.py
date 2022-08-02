#!/usr/bin/python3

"""
``basic domain lib``
===================


"""

import os
import sys
import redis

sys.path.append(os.path.join(os.environ['AIL_BIN'], 'lib/'))
import ConfigLoader

config_loader = ConfigLoader.ConfigLoader()
r_serv_onion = config_loader.get_redis_conn("ARDB_Onion")
config_loader = None

def get_domain_type(domain):
    return 'onion' if str(domain).endswith('.onion') else 'regular'

def delete_domain_item_core(item_id, domain, port):
    domain_type = get_domain_type(domain)
    r_serv_onion.zrem(f'crawler_history_{domain_type}:{domain}:{port}', item_id)
