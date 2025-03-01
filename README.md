# Crash Handler

This is a proof-of-concept implementation for Windows crash handler as hinted
[here](http://www.nynaeve.net/?p=128). The idea is that there is a guarding
process that oversees the child for crashes and writes the minidump if crash
occurs. We cannot do much in the child when crash happens, because program is
not in a known state, so we just copy the crash info and pass it to the parent.
