#!/usr/bin/env python
# -*- coding:utf-8 -*-


"""
==========================
 Word Forensic Correlator
==========================

W4C = Word Forensic Correlator = wor-for-cor = wor4cor = w4c

(c) 2015 W4C = MS Word Forensic Correlator W4C correlates some internal [and not well documented]
Microsoft Word binary document format structures [like FIB private/undocumented/reserved fields].

In digital forensic evidence praxis, there are situations, where is desirable to link questionable
documents to specific MS Word installation. As far as is known, MS Word does not provide any unique
identification like serial number within document itself. W4C is trying to get the unique signature
from files and by comparing these signatures could help to provide percentage hint to user.

W4C is correlation tool for comparing questionable document to reference document. The reference
document is the document we know for sure was edited/saved with specific MS word installation.
The forensic investigation should tell us if other questionable documents were also edited/saved
with some percentage of probability with the same MS-word installation.

W4C calculates internal signature from specific internal fields [can be customized] and then
correlates/compares signature of reference file and tested file. The final matching result is
calculated and shown as correlation percentage. This result could be used in forensic evidence
as helper to proof that document(s) under investigation has/have been edited/saved on the same
MS-word installation as known validated reference document.

W4C is not using well-known MS-Word metadata (like author, dates, version), which can be easily
edited and spoofed. Document size/formatting/contents should have no effect on W4C correlation.


"""

__author__  = 'robert'
__date__    = '2015-03-01'
__version__ = '1.0.5'

import sys
import os

from wordfile import *

class Correlator:
    """
    W4C correlator class
    """

    # defaults
    verbosity = 4

    signature = [ KEY_FIB_PVER, KEY_LANG_STAMP, KEY_CREATED_PRI, KEY_SAVED_PRI, KEY_CREATED_BUILD,
                  KEY_SAVED_BUILD,  '%s^%s' % (KEY_STLSHT_N, KEY_FOOTREF) ]

    def __init__(self, refdoc, tstdoc):
        """
        constructor
        :param refdoc: reference doc filename
        :param tstdoc: tested doc filename
        :return:
        """
        self.ref = WordFile(refdoc)
        self.tst = WordFile(tstdoc)
        return

    def set_signature(self, signature):
        """
        set custom signature for correlation
        :return:
        """
        self.signature = signature
        return

    def get_signature(self, src, frm='%04x', glue='-'):
        """
        get value of signature in hexadecimal format
        :param src:  ref/tst document
        :param frm:  single key format (hexa)
        :param glue: how to glue keys
        :return:
        """
        return glue.join([frm % self._eval_key(src, key) for key in self.signature])

    def _eval_key(self, src, key):
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
            if oper == '^': return src.get(l) ^ src.get(r)
            if oper == '&': return src.get(l) & src.get(r)
            if oper == '|': return src.get(l) | src.get(r)
        return src.get(key)

    def _percent_match(self):
        """
        calculate correlation = signatures percentage match
        :return: float percentage
        """
        total = len(self.signature)
        ok = 0
        self.printout(5, '\n%30s %18s  %18s %s' % ('signature.field', 'reference.value', 'DUT/tested.value', 'result'))
        self.printout(5, '=' * 77)

        for key in self.signature:
            ref = self._eval_key(self.ref, key)
            tst = self._eval_key(self.tst, key)
            if ref == tst: ok += 1
            # details about matching per key
            self.printout(5, '%30s ref.value=0x%06x test.value=0x%06x %s'  % (key, ref, tst, 'match' if ref == tst else '< diff'))
        # calc percentage
        return 100.0*ok/total

    def correlate(self):
        """
        main method for correlation - contains flow and printouts status
        :return:
        """
        # REF DOC
        self.printout(2, '\nReference  document %s' % (self.ref.docname))
        self.ref.parse()
        self.printout(4, 'Validate REF/reference doc: %s\n' % 'OK - valid doc' if self.ref.valid_doc() else 'ERR - invalid doc')

        # TEST DOC
        self.printout(2, 'Tested/DUT document %s' % (self.tst.docname))
        self.tst.parse()
        self.printout(4, 'Validate DUT/tested doc: %s\n' % 'OK - valid doc' if self.tst.valid_doc() else 'ERR - invalid doc')

        # data dump
        if self.verbosity >= 6:
            self.ref.hexdump()
            self.tst.hexdump()
        #
        self.printout(3, '\nReference  document signature: %s' % (self.get_signature(self.ref)))
        self.printout(3, 'Tested/DUT document signature: %s' % (self.get_signature(self.tst)))
        #
        self.printout(1, '\nTested/DUT doc signature is matching REF/reference doc signature for %.2f%%' % self._percent_match())
        return

    def printout(self, level, msg):
        """
        helper to print only if level is equal or over defined verbosity
        :param level:
        :param msg: text to print
        :return:
        """
        if level > self.verbosity: return
        print msg
        return

    @classmethod
    def usage(cls, argv):
        """
        usage help
        :param argv:
        :return:
        """
        list_keys = [', '.join(l) for s,l in WordFile.known_keys.items()]
        print """
        (c) 2015 W4C = MS Word Forensic Correlator [wor-for-cor] version %s by %s

        W4C correlates some internal MS-word doc structures to calculate percentage of probability that
        document under test [test.doc] was edited with the same MS-word version as reference doc [ref.doc]

        usage: %s [-help ][-verbosity int ][-signature csv ] -ref ref.doc test.doc

        help          ... show this usage help
        verbosity int ... optional - set level of verbosity to integer value [default 3]
        signature csv ... optional - use csv fields to calculate signature [see bellow for defaults]
        ref ref.doc   ... reference ms word document
        test.doc      ... documents under test will be correlated to reference one

        Default Signature definition:
        %s

        Signature fields available for CSV:
        %s

        Supported Signature fields logical operators:
        ^ = xor, | = or, & = and

        Single letters instead of descriptive keyword could be used like:
        -v = -verbosity
        -s = -signature
        -r = -ref
        """ % (__version__, __author__, os.path.basename(argv[0]), '-'.join(cls.signature), ', '.join(list_keys))
        sys.exit(1)
        return

    @classmethod
    def execute(cls, argv):
        """
        parse command line parameters and execute correlation
        :param argv:
        :return:
        """
        # min 1+3 arguments: $0 -ref ref.doc test.doc
        if len(argv) < 4:
            cls.usage(argv)

        # parse arguments
        ref = None
        it = iter(argv[1:])
        for par in it:

            # ignore empty values
            if par in ['', ' ']:
                continue

            # help
            if par in ['-h', '-help', '-?']:
                cls.usage(argv)

            # verbosity level
            if par in ['-v', '-verbosity']:
                level = int(next(it))
                cls.verbosity = level
                continue

            # signature csv
            if par in ['-s', '-sig', '-signature']:
                csv = next(it)
                cls.signature = [x.strip() for x in csv.split(',')]
                continue

            # ref doc
            if par in ['-r', '-ref', '-reference', '-m', '-master']:
                ref = next(it)
                continue

            # test doc
            if ref is None:
                cls.usage(argv)
            # correlate
            cor = Correlator(ref, par)
            cor.correlate()

        return

# ======
#  MAIN
# ======

if __name__ == '__main__':

    Correlator.execute(sys.argv)
