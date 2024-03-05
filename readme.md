# ACPU

* Author:  Richard James Howe
* E-mail:  <mailto:howe.r.j.89@gmail.com>
* License: The Unlicense / Public Domain
* Repo:    <https://github.com/howerj/ascii>
* Project: A VM with an ASCII based instruction set

This (silly) project is a work in progress. The idea is to make a
Virtual Machine (VM) that only uses printable ASCII characters as
instructions, just for fun. It might be possible depending on the
choice of instructions to make a VM could in principle be implemented
in hardware on an FPGA. I do not think it is a particularly viable
concept however, and you would be best placed with a more traditional
architecture (and programming language).

One concept (that can be disable at compile time) is to store everything
in memory as ASCII characters as well. For example a 16-bit value would
not take up 2 bytes but instead 4 bytes (so the entire memory is 
readable as text).

The VM implements a 16-bit (although in principle it should be easy
enough to change this) dual-stack stack machine.

Ideally we would make some test programs (such as a monitor, program
loader, Forth interpreter, hexdump utility, etcetera) for the CPU to
tests its functionality.

Jump locations can be stored on the return stack by the VM, however
forward references have to be manually dealt with (and as all programs
are in ASCII all characters need to be accounted for).

As mentioned, this is not a serious project, there are much better
languages out there that could be implemented in roughly the same
amount of code (e.g. Lisp, Forth, an APL like language, prolog, TCL
to name a few) with many examples being scattered across the internet.
