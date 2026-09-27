"""
The JavaScript defects a release is held for.

Same form as `test.lib.scripts.js.test_unfixed_defects`, which these entries were separated out of,
and the same rules: every test states what a correct implementation would do, never what the code
does today, and is marked `unittest.expectedFailure`, so an entry that starts passing is reported as
an unexpected success and leaves this file only by being fixed. Where the question is one about
JavaScript rather than about this project, the answer was established with Node.js and is written
into the row the entry holds, so that the only statement of it is the one that is executed.

What sets these apart is what they cost rather than what they are. Each one takes a program an
engine runs and hands back one that behaves differently: nothing throws, nothing is left
half-rewritten, and the analyst reading it gets no signal that the answer is not the one the
language gives. And each is reached by a shape real input plausibly holds: a wrong answer only
a shape constructed for the defect can reach costs no analyst anything, so it lives in the
other file however wrong it is, with the judgment of its unlikelihood written on the entry. An
entry that merely refuses to reduce something, or reduces it to something uglier, belongs in
the other file as well — unless the refusal forfeits the reduction of a whole class of
input, which costs what a wrong answer costs — and so does everything about a file no
engine runs, however clean the answer for one looks: mishandling invalid input is never what a
release is held for. This file emptying is the release gate.

An entry whose programs are spellings of one root is pinned by one test over all of them. An entry
whose programs have roots a fix may reach separately is pinned by one test per program instead,
installed by `test.lib.scripts.js.ledger.one_expected_failure_per_program` and named for the
shape that program holds: a fix that reaches some of the shapes and not the others is then
reported as a fix rather than as nothing at all, which one test over the whole family cannot do.

No entry stands here now. The last, that converting a function to a string answers the source it
was written with, was fixed by recording each parsed function's source span; its law lives in
`test.lib.scripts.js.deobfuscation.test_function_to_string`.
"""
