"""
The interpreter's line limits: what one physical line of AutoIt3 source may hold. A line of 4094
characters runs and one of 4095 fails to parse, and a line ended by the continuation marker ` _`
joins the lines it spans under no combined bound, so a statement longer than one line is spelled
across continued lines rather than as a line the interpreter refuses. The numbers are probed on
the interpreter itself; the probe scripts and outputs live in `temp/au3_semantics_probe`.
"""

#: The most characters one physical line of AutoIt3 source holds: a 4094-character line runs,
#: a 4095-character line fails to parse.
MAX_LINESIZE = 4094

#: The longest encoded spelling one literal piece may carry: behind a piece on its line stand the
#: widest separator that may follow it — ` Step `, which follows a `For` limit — the continuation
#: marker that ends the line there, and the quotes that enclose the piece itself.
MAX_PIECE_SPELLING = MAX_LINESIZE - len(' Step ') - len(' _') - len('""')
