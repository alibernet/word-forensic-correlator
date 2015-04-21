#!/usr/bin/env python
# -*- coding:utf-8 -*-


"""
==========================
 Word Forensic Correlator
==========================

W4C = Word Forensic Correlator = wor-for-cor = wor4cor = w4c

(c) 2015 W4C = MS Word Forensic Correlator W4C correlates some internal [and not well documented]
Microsoft Word binary document format structures [like FIB private/undocumented/reserved fields].

This is a console version of forensic correlator. For user friendly GUI version check w4c-gui.py

In digital forensic evidence praxis, there are situations, where is desirable to link questionable
documents to specific MS Word installation. As far as is known, MS Word does not provide any unique
identification like serial number within document itself. W4C is trying to get the unique fingerprint
from files and by comparing these fingerprints could help to provide percentage hint to user.

W4C is correlation tool for comparing questionable document to reference document. The reference
document is the document we know for sure was edited/saved with specific MS word installation.
The forensic investigation should tell us if other questionable documents were also edited/saved
with some percentage of probability with the same MS-word installation.

W4C calculates internal fingerprint from specific internal fields [can be customized] and then
correlates/compares fingerprint of reference file and tested file. The final matching result is
calculated and shown as correlation percentage. This result could be used in forensic evidence
as helper to proof that document(s) under investigation has/have been edited/saved on the same
MS-word installation as known validated reference document.

W4C is not using well-known MS-Word metadata (like author, dates, version), which can be easily
edited and spoofed. Document size/formatting/contents should have no effect on W4C correlation.


"""

__author__  = 'Robert'
__email__   = 'robert.puskajler@yahoo.ca'
__version__ = '2.0.1'

import sys
import os

from wordfile import *
import wordfingerprint as wordfp

class Correlator:
    """
    Forensic Correlator class
    """

    # defaults
    refdocfp  = None
    tstdocfp  = None
    verbosity = 4

    def setdoc(self, docname, isref=False):
        """
        set document euther reference or inspected/tested one
        :param docname: document filename
        :param isref: boolean if doc is reference doc or inspected doc
        :return:
        """
        if isref:
            self.refdocfp = wordfp.WordFingerprint(docname)
        else:
            self.tstdocfp = wordfp.WordFingerprint(docname)
        return

    def getmd5(self, isref=False):
        """
        get formatted md5 hash
        :param isref: boolean if doc is reference doc or inspected doc
        :return: string
        """
        return self.refdocfp.md5_formatted() if isref else self.tstdocfp.md5_formatted()

    def getfingerprint(self, isref=False):
        """
        get formatted forensic fingerprint
        :param isref: boolean if doc is reference doc or inspected doc
        :return: string
        """
        return self.refdocfp.fp_formatted() if isref else self.tstdocfp.fp_formatted()

    def getvalidity(self, isref=False):
        """
        get basic ole2 stream validation result
        :param isref: boolean if doc is reference doc or inspected doc
        :return: string describing validation result
        """
        valid = self.refdocfp.wfile.valid_doc() if isref else self.tstdocfp.wfile.valid_doc()
        return 'valid MS-Word/OLE2 document' if valid else 'NOT valid MS-Word/OLE2 document'

    def cancorrelate(self):
        """
        correlator needs reference and inspected doc for calculating result
        :return: boolean
        """
        return self.refdocfp is not None and self.tstdocfp is not None

    def percent_match(self):
        """
        calculate correlation match based on formula - compare ref.doc and tested.doc
        :return: float percentage correlation match
        """
        # stdout - matching table header
        self.printout(5, '\n%30s %8s %8s %s' % ('fingerprint.field', 'ref.val', 'test.val', 'result'))
        self.printout(5, '=' * 55)
        # percent calc init
        total = ok = 0
        for key in self.refdocfp.formula:
            total += 1
            ref = self.refdocfp._eval_key(key)
            tst = self.tstdocfp._eval_key(key)
            if ref == tst: ok += 1
            # stdout - details about matching per key
            self.printout(5, '%30s 0x%06x 0x%06x %s'  % (key, ref, tst, 'match' if ref == tst else '< diff'))
        # calc percentage
        return 100.0*ok/total if total>0 else 0

    def correlate(self):
        """
        main method for console (non GUI) correlation - contains flow and stdout printouts status
        :return:
        """
        # REF DOC
        self.printout(2, '\nReference  document %s' % (self.refdocfp.fname))
        self.printout(4, 'Validate REF/reference doc: %s\n' % self.getvalidity(isref=True))

        # TEST DOC
        self.printout(2, 'Tested/DUT document %s' % (self.tstdocfp.fname))
        self.printout(4, 'Validate DUT/tested doc: %s\n' % self.getvalidity(isref=False))

        # data dump
        if self.verbosity >= 6:
            self.refdocfp.wfile.hexdump()
            self.tstdocfp.wfile.hexdump()
        #
        self.printout(3, '\nReference  document fingerprint: %s' % (self.getfingerprint(isref=True)))
        self.printout(3, 'Tested/DUT document fingerprint: %s'   % (self.getfingerprint(isref=False)))
        #
        if self.cancorrelate():
            self.printout(1, '\nInspected/DUT doc fingerprint is matching REF/reference doc fingerprint for %.2f%%' % self.percent_match())
        return

    def printout(self, level, msg):
        """
        helper to print message to stdout only if verbosity >= level
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
        (c) 2015 W4C = MS Word Forensic Correlator [wor-for-cor] console version %s by %s

        W4C correlates some internal MS-word doc structures to calculate percentage of probability that
        document under test [test.doc] was edited with the same MS-word version as reference doc [ref.doc]

        usage: %s [-help ][-verbosity int ][-fingerprint csv ] -ref ref.doc test.doc

        help            ... show this usage help
        verbosity int   ... optional - set level of verbosity to integer value [default 3]
        fingerprint csv ... optional - use csv fields to calculate fingerprint [see bellow for defaults]
        ref ref.doc     ... reference ms word document
        test.doc        ... inspected documents under test will be correlated to reference one

        Default fingerprint formula definition:
        %s

        Fields available for fingerprint formula listed as CSV:
        %s

        Supported fingerprint fields logical operators:
        ^ = xor, | = or, & = and

        Single letters instead of descriptive keyword could be used like:
        -v = -verbosity
        -f = -fingerprint
        -r = -ref
        """ % (__version__, __author__, os.path.basename(argv[0]), wordfp.WordFingerprint.get_formula(','), ', '.join(list_keys))
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

        # console correlator
        cor = Correlator()
        ref = None

        # parse arguments
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
                cor.verbosity = level
                continue

            # fingerprint csv
            if par in ['-f', '-fingerprint']:
                csv = next(it)
                wordfp.WordFingerprint.set_formula( [x.strip() for x in csv.split(',')] )
                continue

            # ref doc
            if par in ['-r', '-ref', '-reference', '-m', '-master']:
                ref = next(it)
                cor.setdoc(ref, isref=True)
                continue

            # test doc
            if ref is None:
                cls.usage(argv)

            # correlate
            cor.setdoc(par, isref=False)
            cor.correlate()

        return

# ======
#  MAIN
# ======

if __name__ == '__main__':

    Correlator.execute(sys.argv)
