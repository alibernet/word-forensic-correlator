# What is W4C
W4C is helper tool for forensic analyst to link MS word document back to specific 
 MS word installation by creating unique fingerprint from internal binary word document fields.

Stay tuned to more updates coming to W4C ms word forensic fingerprinting ...
 
### Name W4C comes from ...
W4C is short name for Word Forensic Correlator -> wor-for-cor -> wor4cor -> w4c.

### Forensic Question
W4C it doing its best to answer the forensic question: Were two (or more) MS Word
 documents last edited/saved on the same MS Word installation instance ?

Note: sometimes the final answer 42 is not good enough :-)

## How does it work
W4C correlates some internal and not well documented Microsoft Word binary document 
 format structures (like FIB private/undocumented/reserved fields). The final matching result is
 calculated and shown as correlation percentage. This result could be used in forensic evidence
 as helper to proof that document(s) under investigation has/have been edited/saved on the same
 MS-word installation as known validated reference document.

W4C is not using well-known MS Word metadata (like author, dates, version), which can be easily
 edited and spoofed. Document size/formatting/contents should have no effect on W4C correlation.

### Requirements
CLI version: w4c.py     ... python 2.x installed
GUI version: w4c-gui.py ... python 2.x, tkinter installed

Note: self-contained py2exe compiled packages have all dependencies packaged inside package.
 To download windows executable package go to the [release](releases) tab.
 
### Files
    w4c.py              ... CLI version
    w4c-gui.py          ... GUI version
    wordfile.py         ... module for OLE2
    wordfingerprint.py  ... module for fingerprinting
    py2exe/             ... directory for py2exe
    py2exe/setup/py     ... to compile w4c.exe package
    py2exe/setup-gui.py ... to compile w4c-gui.exe package

### How to use CLI version: w4c.py
Model situation: you have one (or more) reference document which was saved/edited on 
 specific MS Word installation under investigation. Now you can use W4C to correlate
 other questionable documents and verify if they were also saved/edited on this MS Word
 installation:

$ ./w4c.py -ref reference.doc investigated.doc

Note: in case of problems try: 

$ python w4c.py 

To get usage help, use -help or execute without any parameters:

        (c) 2015 W4C = MS Word Forensic Correlator [wor-for-cor] version 2.0.1 by robert

        W4C correlates some internal MS-word doc structures to calculate percentage of probability that
        document under test [test.doc] was edited with the same MS-word version as reference doc [ref.doc]

        usage: w4c.py [-help ][-verbosity int ][-fingerprint csv ] -ref ref.doc test.doc

        help            ... show this usage help
        verbosity int   ... optional - set level of verbosity to integer value [default 3]
        fingerprint csv ... optional - use csv fields to calculate fingerprint [see bellow for defaults]
        ref ref.doc     ... reference ms word document
        test.doc        ... documents under test will be correlated to reference one

        Default fingerprint definition:
        product.written.by-language.stamp-created.private-saved.private-created.build-saved.build-stylesheet.len^footref.off

        Fields available for fingerprint CSV:
        signature.magic, created.env, flags.env, fib.magic, fib.ver, product.written.by, language.stamp, autotext.offset,
        flags.doc, fib.min, created.magic, saved.magic, created.private, saved.private, charset.doc, charset.int, 
        saved.build, created.build, key.head.xor, text.offset, stylesheet0.off, stylesheet0.len, stylesheet.off, 
        stylesheet.len, footref.off, footref.len

        Supported fingerprint fields logical operators:
        ^ = xor, | = or, & = and

        Single letters instead of descriptive keyword could be used like:
        -v = -verbosity
        -f = -fingerprint
        -r = -ref

### How to use GUI version: w4c-gui.py
Just start GUI version by executing w4c-gui.py. Then select reference and inspected files through BROWSE button.
After the file is selected, validation result, MD5 hash and forensic fingerprint are shown. When both files are
already selected the final correlation percentage is calculated and shown.

$ ./w4c-gui.py

Note: in case of problems make sure tkinter is installed and themes are configured (ubuntu/kubuntu has broken themes),
 see [_tkinter.TclError](https://jehurst.wordpress.com/tag/tk-interface/) for more details how to fix broken tkinter themes.
 
### Windows Executable
For your convenience Windows 32 bit executables compiled by py2exe are provided in [release](releases) tab. Download the package and unpack it to the working dir.

    w4c-exe.zip is CLI version in single executable file
    w4c-gui.zip is GUI version with all the dependencies
     
#### Pros
W4C by using not well known structures should be more tamper/forgery resistant than any other known forensic tools.
 However, please read section bellow to understand the limits.

#### Cons, Limits
As far as is known, MS Word does not provide any unique identification (like serial number) within document itself. 
 W4C is trying its best to get the unique fingerprint from document file but there is still probability for false positives.
 Exactly the same MS Word installation (and service packs levels and settings) will provide matching fingerprint.
 Also through the time the installed service packs and settings will change which will result to different fingerprint. 
 Therefore it is recommended to use reference document from time range close to questionable ones to eliminate such error. 

#### History
W4C was originally implemented for my father (R.I.P.) working as certified digital forensic analyst. I have decided
 to release it to public just recently in 2015 as I was not able to find any similar tool out there. 

Hope it helps ...

#####keywords: 
microsoft, word, doc, document, ms-word, ole2, digital, forensic, fingerprint, correlate, compare, signature

