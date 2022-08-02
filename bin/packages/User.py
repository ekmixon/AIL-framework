#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import os
import sys
import redis
import bcrypt

sys.path.append(os.path.join(os.environ['AIL_BIN'], 'lib/'))
import ConfigLoader

from flask_login import UserMixin

class User(UserMixin):

    def __init__(self, id):

        config_loader = ConfigLoader.ConfigLoader()

        self.r_serv_db = config_loader.get_redis_conn("ARDB_DB")
        config_loader = None

        self.id = id if self.r_serv_db.hexists('user:all', id) else "__anonymous__"

    # return True or False
    #def is_authenticated():

    # return True or False
    #def is_anonymous():

    @classmethod
    def get(cls, id):
        return cls(id)

    def user_is_anonymous(self):
        return self.id == "__anonymous__"

    def check_password(self, password):
        if self.user_is_anonymous():
            return False

        password = password.encode()
        hashed_password = self.r_serv_db.hget('user:all', self.id).encode()
        return bool(bcrypt.checkpw(password, hashed_password))

    def request_password_change(self):
        return (
            self.r_serv_db.hget(f'user_metadata:{self.id}', 'change_passwd')
            == 'True'
        )

    def is_in_role(self, role):
        return bool(self.r_serv_db.sismember(f'user_role:{role}', self.id))
