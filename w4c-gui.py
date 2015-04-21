#!/usr/bin/env python
# -*- coding:utf-8 -*-


"""
==============================
 Word Forensic Correlator GUI
==============================

W4C = Word Forensic Correlator = wor-for-cor = wor4cor = w4c

(c) 2015 W4C = MS Word Forensic Correlator W4C correlates some internal [and not well documented]
Microsoft Word binary document format structures [like FIB private/undocumented/reserved fields].

This is user friendly GUI/TK frontend for w4c.py console version of forensic correlator.

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

from Tkinter import *
import tkFileDialog
from w4c import *

# Entry read-only state string
#
READONLY='readonly'

# default size / character width for GUI entries
#
DEFSIZE = 58


class DocEntry(Frame):
    """
    word document entry group - renders group box, labels, entries, browse button
    entries: word filename, validation result, md5 hash, correlation fingerprint
    """

    def __init__(self, master, correlator, isref, result, grouplabel='doc', entrylabel='doc', buttontext='Browse'):
        """
        initialize document entry group box with internal variables
        :type master: Application
        :param correlator: instance of Correlator
        :param isref: document is refrence doc
        :param result: strng variable for storing the final percentage result
        :type grouplabel: label for group box
        :type entrylabel: label for filename entry
        :type buttontext: lebel for browse button
        :return:
        """
        Frame.__init__(self, master, class_='DocEntry')
        # store pars
        self.correlator  = correlator
        self.isref       = isref
        self.result      = result
        self.label       = grouplabel
        # local string variables
        self.filename    = StringVar()
        self.md5         = StringVar()
        self.fingerprint = StringVar()
        self.validation  = StringVar()
        # layout
        self.grid()
        self.createWidgets(grouplabel, entrylabel,buttontext)

    def createWidgets(self, grouplabel, entrylabel, buttontext):
        """
        create group box with all GUI elements
        :type grouplabel: label for group box
        :type entrylabel: label for filename entry
        :type buttontext: label for browse button
        :return:
        """
        self.Group = LabelFrame(self, text=grouplabel)
        self.Group.grid(padx=5, ipady=5)

        self.Label = Label(self.Group, text=entrylabel)
        self.Label.grid(column=0, row=0, padx=10, pady=10)

        self.Doc = Entry(self.Group, textvariable=self.filename, width=DEFSIZE)
        self.Doc.grid(column=1, row=0)

        self.Load = Button(self.Group, text=buttontext, command=self.selectFile)
        self.Load.grid(column=2, row=0, padx=10)

        self.ValidLabel = Label(self.Group, text="Valiadation:")
        self.ValidLabel.grid(column=0, row=1, padx=10)
        self.DocValid = Entry(self.Group, textvariable=self.validation, state=READONLY, justify=CENTER, width=DEFSIZE)
        self.DocValid.grid(column=1, row=1)

        self.Md5Label = Label(self.Group, text="MD5 Hash:")
        self.Md5Label.grid(column=0, row=2, padx=10, pady=2)
        self.Md5Entry = Entry(self.Group, textvariable=self.md5, state=READONLY, justify=CENTER, width=DEFSIZE)
        self.Md5Entry.grid(column=1, row=2)

        self.FingerLabel = Label(self.Group, text="Fingerprint:")
        self.FingerLabel.grid(column=0, row=3, padx=10, pady=2)
        self.FingerRef = Entry(self.Group, textvariable=self.fingerprint, state=READONLY, justify=CENTER, width=DEFSIZE)
        self.FingerRef.grid(column=1, row=3)

    def selectFile(self):
        """
        browse button dialog handler
        :return:
        """
        # execute modal dialog
        filename = tkFileDialog.askopenfilename(defaultextension='.doc',
                                        filetypes = [('ms-word doc', '.doc'), ('all files', '.*')],
                                        parent=self,
                                        title='Select%s' % self.label)
        # process filename
        self.processFile(filename)
        return

    def processFile(self, filename):
        """
        process file identified by filename - validate, get hash, fingerprint
        optional - calculate correlation result if has reference and tested doc
        """
        if not filename: return

        # to GUI
        self.filename.set(filename)
        # to Correlator()
        self.correlator.setdoc(filename, self.isref)
        # validate
        self.validation.set(self.correlator.getvalidity(self.isref))
        # hash
        self.md5.set(self.correlator.getmd5(self.isref))
        # correlation fingerprint
        self.fingerprint.set(self.correlator.getfingerprint(self.isref))

        # if has both files (reference and inspected one) do the correlation
        if self.correlator.cancorrelate():
            self.result.set('%.2f %%' % self.correlator.percent_match())

        return


class Application(Frame):
    """
    GUI correlator frontend app
    """

    def __init__(self, master=None):
        """
        initialize GUI and layout
        :type master: Tkinter.Tk
        :return:
        """
        Frame.__init__(self, master)
        self.grid(padx=10, pady=10)
        self.createWidgets()

    def createWidgets(self):
        """
        create required GUI widgets
        :return:
        """
        # correlator
        self.correlator = Correlator()

        # final percentage result
        self.result = StringVar()

        # REFERENCE doc
        self.RefDoc = DocEntry(self, self.correlator, True, self.result, grouplabel=" Reference document ", entrylabel="File:")
        self.RefDoc.grid(column=0, row=0)

        # INSPECTED/correlated/tested doc
        self.TstDoc = DocEntry(self, self.correlator, False, self.result, grouplabel=" Inspected document ", entrylabel="File:")
        self.TstDoc.grid(column=0, row=1)

        # correlation formula
        self.FormulaGroup = LabelFrame(self, padx=5, pady=5, text=" Correlation Fingerprint Formula ")
        self.FormulaGroup.grid(ipadx=0, pady=5)
        self.formula = StringVar()
        self.formula.set(wordfp.WordFingerprint.get_formula())
        self.Formula = Entry(self.FormulaGroup, textvariable=self.formula, state=READONLY, justify=CENTER, width=DEFSIZE+22)
        self.Formula.grid(column=1, row=2)

        # final result
        self.Group = LabelFrame(self, padx=5, pady=5, text=" Correlation Result ")
        self.Group.grid(ipadx=10, pady=5)
        self.Label = Label(self.Group, text="Reference word document and Inspected word document fingerprint correlates for")
        self.Label.grid(column=0, row=0, padx=17)
        self.Percent = Entry(self.Group, textvariable=self.result, justify=CENTER, width=10)
        self.Percent.grid(column=1, row=0)

    @classmethod
    def main(cls, argv):
        """
        execute GUI frontend for correlator
        :return:
        """
        root = Tk()
        app = Application(master=root)
        app.master.title('MS Word Forensic Correlator - GUI ver %s by %s' % (__version__, __author__))
        app.mainloop()

# ======
#  MAIN
# ======

if __name__ == '__main__':

    Application.main(sys.argv)
