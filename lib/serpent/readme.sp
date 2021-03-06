This archive contains Pascal/Delphi sources for the Serpent cipher.

Serpent (designed by Ross Anderson, Eli Biham, and Lars Knudsen) was one
of the AES finalists; it is a 128-bit block cipher with key sizes of
128, 192, or 256 bits. Pascal software implementations are very slow
compared to AES/Rijndael. Please note that although my code supports
OMAC and EAX, these modes are not tested against public test vectors
(the usual C libraries do either not implement Serpent or OMAC/EAX).

There is code for a DLL and the following modes of operation are
supported: CBC, CFB128, CTR, ECB,OFB, OMAC, and EAX. All modes allow
plain and cipher text lengths that need not be multiples of the block
length (for ECB and CBC cipher text stealing is used for the short
block). CTR mode can use 4 built-in incrementing functions or a user
supplied one, and provides seek functions for random access reads.

All modes of operation (except OMAC/EAX) support a reset function that
re-initializes the chaining variables without the recalculation of the
round keys.

Last changes (Jan. 2013)
- Adjustments (test programs) for D17 (XE3), {$J+} if needed
