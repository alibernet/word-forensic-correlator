#!/usr/bin/env python
# -*- coding:utf-8 -*-


"""
===========
 Word File
===========

Word File is helper module for W4C = Word Forensic Correlator = wor-for-cor = wor4cor = w4c

"""

__author__  = 'Robert'
__email__   = 'robert.puskajler@yahoo.ca'
__version__ = '2.0.1'

import struct
import traceback

# CONST
# =====

# magic numbers
OLE2_MAGIC = 0xE11AB1A1E011CFD0
FIB_MAGIC  = 0xA5EC
WORD_MAGIC = 0x6A62

# file offsets
FIB_START  = 0x200
FIB_RGW97  = 0x222
FIB_RGLW97 = 0x244
FIB_TAB97  = 0x29a

# keys
KEY_DOC_MAGIC       = 'signature.magic'
#
KEY_FIB_MAGIC       = 'fib.magic'
KEY_FIB_VER         = 'fib.ver'
KEY_FIB_PVER        = 'product.ver'
KEY_LANG_STAMP      = 'lang.stamp'
KEY_AUTO_TEXT       = 'autotext.off'
KEY_FLAGS_DOC       = 'flags.doc'
KEY_FIB_MIN         = 'fib.min'
KEY_HEAD_XOR        = 'key.head.xor'
KEY_CREATED_ENV     = 'created.env'
KEY_FLAGS_ENV       = 'flags.env'
KEY_CHARSET_DOC     = 'charset.doc'
KEY_CHARSET_INT     = 'charset.int'
KEY_TXT_OFFSET      = 'text.offset'
#
KEY_CREATED_MAGIC   = 'created.magic'
KEY_CREATED_PRI     = 'created.priv'
KEY_CREATED_BUILD   = 'created.build'
KEY_SAVED_MAGIC     = 'saved.magic'
#
KEY_STLSHT_ORG      = 'stylesheet0.off'
KEY_STLSHT_ORG_N    = 'stylesheet0.len'
KEY_STLSHT          = 'stylesheet.off'
KEY_STLSHT_N        = 'stylesheet.len'
KEY_FOOTREF         = 'footref.off'
KEY_FOOTREF_N       = 'footref.len'
#
KEY_SAVED_PRI       = 'saved.priv'
KEY_SAVED_BUILD     = 'saved.build'


class WordFile:
    """
    Class for reading MS word file binary structures
    """

    # known fields/keys grouped by size in bytes
    known_keys = {
        8:  [ KEY_DOC_MAGIC ],
        4:  [ KEY_SAVED_BUILD,  KEY_CREATED_BUILD,  KEY_HEAD_XOR,   KEY_TXT_OFFSET,
              KEY_STLSHT_ORG,   KEY_STLSHT_ORG_N,   KEY_STLSHT,     KEY_STLSHT_N,
              KEY_FOOTREF,      KEY_FOOTREF_N
            ],
        2:  [
              KEY_FIB_MAGIC,    KEY_FIB_VER,        KEY_FIB_PVER,   KEY_LANG_STAMP,
              KEY_AUTO_TEXT,    KEY_FLAGS_DOC,      KEY_FIB_MIN,    KEY_CREATED_MAGIC,
              KEY_SAVED_MAGIC,  KEY_CREATED_PRI,    KEY_SAVED_PRI,
              KEY_CHARSET_DOC,  KEY_CHARSET_INT
            ],
        1:  [ KEY_CREATED_ENV,  KEY_FLAGS_ENV ],
    }

    # size in bytes to struct format character
    size_format = {
        8:  'Q',
        4:  'L',
        2:  'H',
        1:  'B'
    }

    def __init__(self, docname):
        """
        constructor
        :param docname: ms word filename
        :return:
        """
        self.docname = docname
        self.doc = {}
        return

    def _key_size(self, key):
        """
        reverse lookup for known_keys - get key size in bytes by key name
        :param key: keyname in ascii string
        :return:
        """
        for size in self.known_keys:
            if key in self.known_keys[size]:
                return size
        return 0

    def _key_to_format(self, key, frm='<%s'):
        """
        get struct format from key name
        :param key: keyname
        :param frm: format string (endian)
        :return:
        """
        size = self._key_size(key)
        char = self.size_format.get(size)
        return frm % char

    def _read(self, f, frm):
        """
        read binary bytes from file f defined by format frm
        :param frm: struct format
        :param f: file
        :return: read unpacked data
        """
        return struct.unpack(frm, f.read(struct.calcsize(frm)))[0]

    def _read_key(self, f, key):
        """
        read binary bytes specified by keyname
        :param f: file
        :param key: keyname
        :return:
        """
        self.doc[key] = self._read(f, self._key_to_format(key))
        return

    def _read_magic(self, f):
        """
        read magic signature
        :param f: file
        :return:
        """
        #
        f.seek(0)
        # magic signature
        self._read_key(f, KEY_DOC_MAGIC)
        return

    def _read_fib(self, f):
        """
        read interesting FIB fields
        :param f: file
        :return: fills up internal dictionary doc
        """
        # fib static
        f.seek(FIB_START)
        for k in [ KEY_FIB_MAGIC, KEY_FIB_VER, KEY_FIB_PVER, KEY_LANG_STAMP,
            KEY_AUTO_TEXT, KEY_FLAGS_DOC, KEY_FIB_MIN, KEY_HEAD_XOR, KEY_CREATED_ENV, KEY_FLAGS_ENV,
            KEY_CHARSET_DOC, KEY_CHARSET_INT, KEY_TXT_OFFSET ]:
                self._read_key(f, k)
        #
        # fib dynamic short
        f.seek(FIB_RGW97)
        for k in [KEY_CREATED_MAGIC, KEY_SAVED_MAGIC, KEY_CREATED_PRI, KEY_SAVED_PRI]:
            self._read_key(f, k)
        #
        # fib tab97
        f.seek(FIB_TAB97)
        for k in [KEY_STLSHT_ORG, KEY_STLSHT_ORG_N, KEY_STLSHT, KEY_STLSHT_N, KEY_FOOTREF, KEY_FOOTREF_N]:
            self._read_key(f, k)
        #
        # fib dynamic long
        f.seek(FIB_RGLW97)
        for k in [KEY_CREATED_BUILD, KEY_SAVED_BUILD]:
            self._read_key(f, k)
        return

    def _parse_doc(self, doc):
        """
        parse ms word file - read magic and FIB, handle errors
        :param doc: filename
        :return:
        """
        try:
            with open(doc, 'rb') as f:
                self._read_magic(f)
                self._read_fib(f)
        except IOError as e:
            print e
        except :
            print traceback.format_exc()

        return

    def parsed(self):
        """
        doc was parsed into dictionary
        :return:
        """
        return len(self.doc) > 0

    def valid_doc(self):
        """
        validate few internal magic numbers to validate if parsed file is word document
        :param f:
        :return:
        """
        return  self.parsed() \
            and self.assert_equal(self.get(KEY_DOC_MAGIC), OLE2_MAGIC, None) \
            and self.assert_equal(self.get(KEY_FIB_MAGIC), FIB_MAGIC, None) \
            and self.assert_equal(self.get(KEY_CREATED_MAGIC), WORD_MAGIC, None) \
            and self.assert_equal(self.get(KEY_SAVED_MAGIC), WORD_MAGIC, None)

    def assert_equal(self, actual, expected, msg='ERROR: actual($actual) != expected($expected)'):
        """
        assertion used for validation
        :param actual:
        :param expected:
        :param msg: optional msg to show
        :return:
        """
        if actual == expected: return True
        if msg: print msg.replace('$actual', '0x%x' % actual).replace('$expected', '0x%x' % expected)
        return False

    def parse(self):
        """
        parse document - wrapper for _parse_doc() for future extensions
        :param doc:
        :return:
        """
        self._parse_doc(self.docname)
        return

    def hexdump(self):
        """
        dump parsed doc structure in hexa
        :return:
        """
        print "HEXDUMP DOC file:%s:" % self.docname
        for s,lst in self.known_keys.items():
            for k in lst:
                print "%20s: %s" % (k, self.hexa_key(k))
        print
        return

    def hexa_key(self, key):
        """
        single key hexa format with correct size
        :param key:
        :return:
        """
        size = self._key_size(key)
        frm = '0x%%0%dx' % size
        return frm % self.get(key)

    def get(self, key):
        """
        get value of internal key specified by keyname in ascii
        :param key:
        :return:
        """
        return self.doc.get(key, 0)
