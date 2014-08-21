#!/usr/bin/python2.7

"""
The ``Paste Class``
===================

Use it to create an object from an existing paste or other random file.

Conditions to fulfill to be able to use this class correctly:
-------------------------------------------------------------

1/ The paste need to be saved on disk somewhere (have an accessible path)
2/ The paste need to be gziped.
3/ The filepath need to look like something like this:
    /directory/source/year/month/day/paste.gz

"""

import os
import magic
import gzip
import pprint
import redis
import operator
import string
import re
import json
import ConfigParser
import cStringIO
from Date import Date
from Hash import Hash

from langid.langid import LanguageIdentifier, model

from nltk.tokenize import RegexpTokenizer
from textblob import TextBlob

clean = lambda dirty: ''.join(filter(string.printable.__contains__, dirty))
"""It filters out non-printable characters from the string it receives."""


class Paste(object):
    """
    This class representing a Paste as an object.
    When created, the object will have by default some "main attributes"
    such as the size or the date of the paste already calculated, whereas other
    attributes are not set and need to be "asked to be calculated" by their
    methods.
    It was design like this because some attributes take time to be calculated
    such as the langage or the duplicate...

    :Example:

    PST = Paste("/home/2013/ZEeGaez5.gz")

    """

    def __init__(self, p_path):

        configfile = os.path.join(os.environ('AIL_BIN'), 'packages/config.cfg')
        if not os.path.exists(configfile):
            raise Exception('Unable to find the configuration file. \
                            Did you set environment variables? \
                            Or activate the virtualenv.')

        cfg = ConfigParser.ConfigParser()
        cfg.read(configfile)
        self.cache = redis.StrictRedis(
            host=cfg.get("Redis_Queues", "host"),
            port=cfg.getint("Redis_Queues", "port"),
            db=cfg.getint("Redis_Queues", "db"))
        self.store = redis.StrictRedis(
            host=cfg.get("Redis_Data_Merging", "host"),
            port=cfg.getint("Redis_Data_Merging", "port"),
            db=cfg.getint("Redis_Data_Merging", "db"))

        self.p_path = p_path
        self.p_name = os.path.basename(self.p_path)
        self.p_size = round(os.path.getsize(self.p_path)/1024.0, 2)
        self.p_mime = magic.from_buffer(self.get_p_content(), mime=True)

        # Assuming that the paste will alway be in a day folder which is itself
        # in a month folder which is itself in a year folder.
        # /year/month/day/paste.gz
        var = self.p_path.split('/')
        self.p_date = Date(var[-4], var[-3], var[-2])
        self.p_source = var[-5]

        self.p_encoding = None
        self.p_hash_kind = None
        self.p_hash = None
        self.p_langage = None
        self.p_nb_lines = None
        self.p_max_length_line = None

    def get_p_content(self):
        """
        Returning the content of the Paste

        :Example:

        PST.get_p_content()

        """

        paste = self.cache.get(self.p_path)
        if paste is None:
            with gzip.open(self.p_path, 'rb') as f:
                paste = f.read()
                self.cache.set(self.p_path, paste)
                self.cache.expire(self.p_path, 300)
        return paste

    def get_p_content_as_file(self):
        return cStringIO.StringIO(self.get_p_content())

    def get_lines_info(self):
        """
        Returning and setting the number of lines and the maximum lenght of the
        lines of the paste.

        :return: tuple (#lines, max_length_line)

        :Example: PST.get_lines_info()

        """
        if self.p_nb_lines is None or self.p_max_length_line is None:
            max_length_line = 0
            f = self.get_p_content_as_file()
            line_id = 0
            for line_id, line in enumerate(f):
                length = len(line)
                if length >= max_length_line:
                    max_length_line = length
            f.close()
            self.p_nb_lines = line_id
            self.p_max_length_line = max_length_line
        return (self.p_nb_lines, self.p_max_length_line)

    def _get_p_encoding(self):
        """
        Setting the encoding of the paste.

        :Example: PST._set_p_encoding()

        """
        return self.p_mime

    def _set_p_hash_kind(self, hashkind):
        """
        Setting the hash (as an object) used for futur operation on it.

        :Example: PST._set_p_hash_kind("md5")

        .. seealso:: Hash.py Object to get the available hashs.

        """
        self.p_hash_kind = Hash(hashkind)

    def _get_p_hash(self):
        """
        Setting the hash of the paste as a kind of "uniq" identificator

        :return: hash string (md5, sha1....)

        :Example: PST._get_p_hash()

        .. note:: You need first to "declare which kind of hash you want to use
        before using this function
        .. seealso:: _set_p_hash_kind("md5")

        """
        self.p_hash = self.p_hash_kind.Calculate(self.get_p_content())
        return self.p_hash

    def _get_p_language(self):
        """
        Returning and setting the language of the paste (guessing)

        :Example: PST._get_p_language()

        ..note:: The language returned is purely guessing and may not be accurate
        if the paste doesn't contain any human dictionnary words
        ..seealso: git@github.com:saffsd/langid.py.git

        """
        identifier = LanguageIdentifier.from_modelstring(model, norm_probs=True)
        return identifier.classify(self.get_p_content())

    def _get_p_hash_kind(self):
        return self.p_hash_kind

    def _get_p_date(self):
        return self.p_date

    def _get_hash_lines(self, min=1, start=1, jump=10):
        """
        Returning all the lines of the paste hashed.

        :param min: -- (int) Minimum line length to be hashed.
        :param start: -- (int) Number the line where to start.
        :param jump: -- (int) Granularity of the hashing 0 or 1 means no jumps
        (Maximum Granularity)

        :return: a set([]) of hash.

        .. warning:: Using a set here mean that this function will only return uniq hash.

        If the paste is composed with 1000 time the same line, this function will return
        just once the line.

        This choice was made to avoid a certain redundancy and useless hash checking.

        :Example: PST._get_hash_lines(1, 1, 0)

        .. note:: You need first to "declare which kind of hash you want to use
        before using this function
        .. seealso:: _set_p_hash_kind("md5")

        """
        S = set([])
        f = self.get_p_content_as_file()
        for num, line in enumerate(f, start):
            if len(line) >= min:
                if jump > 1:
                    if (num % jump) == 1:
                        S.add(self.p_hash_kind.Calculate(line))
                else:
                    S.add(self.p_hash_kind.Calculate(line))
        return S

    def is_duplicate(self, obj, min=1, percent=50, start=1, jump=10):
        """
        Returning the percent of similarity with another paste.
        ( Using the previous hashing method )

        :param obj: (Paste) The paste to compare with
        :param min: -- (int) Minimum line length to be hashed.
        :param percent: -- (int)
        :param start: -- (int) Number the line where to start.
        :param jump: -- (int) Granularity of the hashing 0 or 1 means no jumps
        (Maximum Granularity)

        :return: (tuple) (bool, percent)

        :Example:
        PST.is_duplicate(PST)

        >>> return (True, 100.0)

        ..seealso: _get_hash_lines()

        """

        set1 = self._get_hash_lines(min, start, jump)
        set2 = obj._get_hash_lines(min, start, jump)

        inter = set.intersection(set1, set2)

        numerator = len(inter)
        denominator = float((len(set1) + len(set2)) / 2)

        try:
            var = round((numerator / denominator)*100, 2)
        except ZeroDivisionError:
            var = 0.0

        if var >= percent:
            return True, var
        else:
            return False, var

    def save_all_attributes_redis(self, key=None):
        """
        Saving all the attributes in a "Redis-like" Database (Redis, LevelDB)

        :param r_serv: -- Connexion to the Database.
        :param key: -- Key of an additionnal set.

        Example:
        import redis

        r_serv = redis.StrictRedis(host = 127.0.0.1, port = 6739, db = 0)

        PST = Paste("/home/Zkopkmlk.gz")
        PST.save_all_attributes_redis(r_serv)

        """
        # LevelDB Compatibility
        p = self.store.pipeline(False)
        p.hset(self.p_path, "p_name", self.p_name)
        p.hset(self.p_path, "p_size", self.p_size)
        p.hset(self.p_path, "p_mime", self.p_mime)
        # p.hset(self.p_path, "p_encoding", self.p_encoding)
        p.hset(self.p_path, "p_date", self._get_p_date())
        p.hset(self.p_path, "p_hash_kind", self._get_p_hash_kind())
        p.hset(self.p_path, "p_hash", self.p_hash)
        # p.hset(self.p_path, "p_langage", self.p_langage)
        # p.hset(self.p_path, "p_nb_lines", self.p_nb_lines)
        # p.hset(self.p_path, "p_max_length_line", self.p_max_length_line)
        # p.hset(self.p_path, "p_categories", self.p_categories)
        p.hset(self.p_path, "p_source", self.p_source)
        if key is not None:
            p.sadd(key, self.p_path)
        else:
            pass
        p.execute()

    def save_attribute_redis(self, attr_name, value):
        """
        Save an attribute as a field
        """
        if type(value) == set:
            self.store.hset(self.p_path, attr_name, json.dumps(list(value)))
        else:
            self.store.hset(self.p_path, attr_name, json.dumps(value))

    def _get_from_redis(self, r_serv):
        return r_serv.hgetall(self.p_hash)

    def _get_top_words(self, sort=False):
        """
        Tokenising method: Returning a sorted list or a set of paste's words

        :param sort: Selecting the output: sorted list or a set. (set by default)

        :return: set or sorted list of tuple [(word, occurency)...]

        :Example: PST._get_top_words(False)

        """
        words = {}
        tokenizer = RegexpTokenizer('[\&\~\:\;\,\.\(\)\{\}\|\[\]\\\\/\-/\=\'\"\%\$\?\@\+\#\_\^\<\>\!\*\n\r\t\s]+',
                                    gaps=True, discard_empty=True)

        blob = TextBlob(clean(self.get_p_content()), tokenizer=tokenizer)

        for word in blob.tokens:
            if word in words.keys():
                num = words[word]
            else:
                num = 0
            words[word] = num + 1
        if sort:
            var = sorted(words.iteritems(), key=operator.itemgetter(1), reverse=True)
        else:
            var = words

        return var

    def _get_word(self, word):
        """
        Returning a specific word and his occurence if present in the paste

        :param word: (str) The word

        :return: (tuple) ("foo", 1337)

        """
        return [item for item in self._get_top_words() if item[0] == word]

    def get_regex(self, regex):
        """
        Returning matches with the regex given as an argument.

        :param regex: -- (str) a regex

        :return: (list)

        :Example: PST.get_regex("4[0-9]{12}(?:[0-9]{3})?")


        """
        matchs = []
        for match in re.findall(regex, self.get_p_content()):
            if match != '' and len(match) < 100:
                matchs.append(match)
        return matchs


if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=4)
    main()
