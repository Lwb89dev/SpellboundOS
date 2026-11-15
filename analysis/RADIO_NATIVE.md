# Experimental ARM Thumb analysis of the radio images

The radio loader's record addresses and 512-byte skips provide a candidate
mapping for the extracted images. A separate Ghidra project imports the bytes
after each 512-byte prefix at that record's address. The 15 mapped ranges do
not overlap in this OTA. Two plausible Thumb starts occur a further `0x400`
bytes into the mapped bodies, corresponding to offset `0x600` of complete
extracted records 03 and 13.

Using Ghidra 12.1.2 `ARM:LE:32:Cortex`, setting TMode=1 at candidate addresses
`0x0209a400` and `0x02015400`, and following analysis produces recognizable
startup-like functions. They copy data between pointer ranges and zero other
ranges; the first also calls two indirect function pointers. This supports
Thumb-code interpretation of these parts, but neither the actual radio CPU
model nor every segment's code/data layout has been verified. External ROM
addresses and some instruction flows remain unresolved.

`analysis_scripts/decompile_radio.py --ghidra /absolute/path/to/analyzeHeadless`
prepares fresh local bodies and a mapping file, imports them with
`SeedRadio.java`, and exports inferred functions through `ExportFunctions.java`.
The reproduction wrapper is restricted to the investigated radio package hash
because its mapping assumptions are specific to this artifact. Existing output
directories are not reused.

Local first-pass outputs are in `firmware/decompiled/radio/`, with individual
statuses in functions.tsv. Pseudocode output is an analysis artifact and has
not been executed or tested as replacement radio firmware. It includes
incomplete functions and can misidentify data as instructions. The main
processor's AndeStar profile is not used for this candidate radio corpus.
