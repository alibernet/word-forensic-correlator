# Name W4C comes from ...
W4C is short name for Word Forensic Correlator -> wor-for-cor -> wor4cor -> w4c.

# What is W4C
W4C is helper tool for forensic analyst to link MS word document back to specific 
 MS word installation by creating unique signature from internal word document fields.

# Forensic Question
W4C it doing its best to answer the forensic question: Were two (or more) MS Word
 documents last edited/saved on the same MS Word installation instance ?
 Note: sometimes the final answer 42 is not good enough :-)

# How does it work
W4C correlates some internal and not well documented Microsoft Word binary document 
 format structures (like FIB private/undocumented/reserved fields). The final matching result is
 calculated and shown as correlation percentage. This result could be used in forensic evidence
 as helper to proof that document(s) under investigation has/have been edited/saved on the same
 MS-word installation as known validated reference document.

W4C is not using well-known MS Word metadata (like author, dates, version), which can be easily
 edited and spoofed. Document size/formatting/contents should have no effect on W4C correlation.

# Requirements
python 2.x installed, will try to provide GUI and self-contained exe later

# How to use
Model situation: you have one (or more) reference document which was saved/edited on 
 specific MS Word installation under investigation. Now you can use W4C to correlate
 other questionable documents and verify if they were also saved/edited on this MS Word
 installation:

$ ./w4c.py -ref my_reference.doc under_question.doc

Note: in case of problems try: 

$ python w4c.py 

To get usage help, use -help or execute without any parameters:

    (c) 2015 W4C = MS Word Forensic Correlator [wor-for-cor] version 1.0.5 by robert
    
    W4C correlates some internal MS-word doc structures to calculate percentage of probability that
    document under test [test.doc] was edited with the same MS-word version as reference doc [ref.doc]
    
    usage: w4c.py [-help ][-verbosity int ][-signature csv ] -ref ref.doc test.doc
    
    help          ... show this usage help
    verbosity int ... optional - set level of verbosity to integer value [default 3]
    signature csv ... optional - use csv fields to calculate signature [see bellow for defaults]
    ref ref.doc   ... reference ms word document
    test.doc      ... documents under test will be correlated to reference one
    
    Default Signature definition:
    product.written.by-language.stamp-created.private-saved.private-created.build-saved.build-stylesheet.len^footref.off
    
    Signature fields available for CSV:
    signature.magic, created.env, flags.env, fib.magic, fib.ver, product.written.by, language.stamp, autotext.offset, 
    flags.doc, fib.min, created.magic, saved.magic, created.private, saved.private, charset.doc, charset.int, saved.build, 
    created.build, key.head.xor, text.offset, stylesheet0.off, stylesheet0.len, stylesheet.off, stylesheet.len, 
    footref.off, footref.len
    
    Supported Signature fields logical operators:
    ^ = xor, | = or, & = and
    
    Single letters instead of descriptive keyword could be used like:
    -v = -verbosity
    -s = -signature
    -r = -ref

# Pros
W4C by using not well known structures should be more tamper/forgery resistant than any other known forensic tools.
 However, please read section bellow to understands the limits.

# Cons, Limits
As far as is known, MS Word does not provide any unique identification (like serial number) within document itself. 
 W4C is trying ts best to get the unique signature from document file but there is still probability for false positives.
 Exactly the same MS Word installation (and service packs levels and settings) will provide matching signature.
 Also through the time service packs and settings will change which will result to different signature. Therefore is
 recommended to use reference document from time range close to questionable ones to eliminate such error. 
 
# History
W4C was originally implemented for my father (R.I.P.) working as certfied digital forensic analyst. I have decided
 to release it to public just recently in 2015 as I was not able to find any similar tool out there. 

Hope it helps ...


