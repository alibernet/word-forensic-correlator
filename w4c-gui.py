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

__author__  = 'robert'
__date__    = '2015-03-01'
__version__ = '1.0.6'

from Tkinter import *


class DocEntry(Frame):

    def __init__(self, master, grouplabel='doc', entrylabel='doc', buttontext='Load'):
        Frame.__init__(self, master, class_='DocEntry')
        self.createWidgets(grouplabel, entrylabel,buttontext)

    def createWidgets(self, grouplabel, entrylabel, buttontext):
        self.Group = LabelFrame(self, padx=5, pady=5, text=grouplabel)
        self.Group.grid()

        self.Label = Label(self.Group, text=entrylabel)
        self.Label.grid(column=0, row=0)

        self.Doc = Entry(self.Group)
        self.Doc.grid(column=1, row=0)

        self.Load = Button(self.Group, text=buttontext, command=self.quit)
        self.LoadRef.grid(column=2, row=0)


class Application(Frame):

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.grid()
        self.createWidgets()

    def createWidgets(self):

        self.GroupRef = LabelFrame(self, padx=5, pady=5, text="Reference document:")
        self.GroupRef.pack(fill="both", expand="yes")

        self.LblRef = Label(self.GroupRef, text="Refrence doc:")
        self.LblRef.pack()
        #self.LblRef.grid(column=0, row=0)
        self.DocRef = Entry(self.GroupRef)
        self.DocRef.pack()
        #self.DocRef.grid(column=1, row=0)
        self.LoadRef = Button(self.GroupRef, text="Load Ref. doc", command=self.quit)
        self.LoadRef.pack()
        #self.LoadRef.grid(column=2, row=0)

#        self.LblRefFinger = Label(self, text="Fingerprint:")
#        self.LblRefFinger.grid(column=0, row=1)
#        self.FingerRef = Entry(self, state=DISABLED)
#        self.FingerRef.grid(column=1, row=1)

#        self.Line = Canvas(self)
#        self.Line.create_line(0,0, 500,0, width=10)
#        self.Line.grid(columnspan=3)

#        self.LblTst = Label(self, text="Tested doc:")
#        self.LblTst.grid(column=0, row=2)
#        self.DocTst = Entry(self)
#        self.DocTst.grid(column=1, row=2)
#        self.LoadTst = Button(self, text="Load Test doc", command=self.quit)
#        self.LoadTst.grid(column=2, row=2)

    def say_hi(self):
        print "hi there, everyone!"




# ======
#  MAIN
# ======

if __name__ == '__main__':

    root = Tk()
    app = Application(master=root)
    app.master.title('Word Forensic Correlator')
    app.mainloop()
    root.destroy()
