#!/usr/bin/env python
# -*- coding:utf-8 -*-


"""
=================
 Word Fingerprint
=================

Word Fingerprint is helper module for W4C = Word Forensic Correlator = wor-for-cor = wor4cor = w4c

Generates customizable ms-word file fingerprints

"""

__author__  = 'Robert'
__email__   = 'robert.puskajler@yahoo.ca'
__version__ = '2.0.1'

import hashlib

from wordfile import *

class WordFingerprint:
    """
    Forensic MS Word file fingerprint
    """

    # default formula for forensic fingerprint
    #
    formula = [ KEY_FIB_PVER, KEY_LANG_STAMP, KEY_CREATED_PRI, KEY_SAVED_PRI, KEY_CREATED_BUILD,
        KEY_SAVED_BUILD,  '%s^%s' % (KEY_STLSHT_N, KEY_FOOTREF)
    ]

    def __init__(self, fname=None):
        """
        initilize forensic fingerprint
        :param fname:
        :return:
        """
        if fname: self.filename(fname)

    def filename(self, fname):
        """
        set ms word filename and parse ole2 stream
        :param fname:
        :return:
        """
        self.fname = fname
        self.wfile = WordFile(fname)
        self.wfile.parse()

    def md5(self):
        """
        calculate md5 hash
        :return:
        """
        buffsize = 65536
        hash = hashlib.md5()
        with open(self.fname, 'rb') as f:
            for block in iter(lambda: f.read(buffsize), ''):
                hash.update(block)
        return hash.hexdigest()

    def md5_formatted(self, groupby=4, glue='-'):
        """
        return formatted md5 hash
        :param groupby: number of hexa digits in one group
        :param glue: char to glue result
        :return:
        """
        return glue.join( map(''.join, zip(*[ iter(self.md5()) ]*groupby) ) )

    @classmethod
    def set_formula(cls, formula):
        """
        set other than default formula for forensic fingerprint
        :param formula:
        :return:
        """
        cls.formula = formula
        return

    @classmethod
    def get_formula(cls, glue='-'):
        """
        get forensic fingerprint formula
        :param glue: char to glue keys for formula
        :return:
        """
        return glue.join(cls.formula)

    def fp_formatted(self, frm='%04x', glue='-'):
        """
        get value of forensic fingerprint in hexadecimal format
        :param src:  ref/tst document
        :param frm:  single key format (hexa)
        :param glue: how to glue keys
        :return:
        """
        return glue.join([frm % self._eval_key(key) for key in self.formula])

    def _eval_key(self, key):
        """
        evaluate key if logical operator is used
        :param src:
        :param key: keyname or logical expression
        :return:
        """
        for oper in '^|&':
            if oper not in key: continue
            l,r = key.split(oper)
            l,r = l.strip(),r.strip()
            if oper == '^': return self.wfile.get(l) ^ self.wfile.get(r)
            if oper == '&': return self.wfile.get(l) & self.wfile.get(r)
            if oper == '|': return self.wfile.get(l) | self.wfile.get(r)
        return self.wfile.get(key)
