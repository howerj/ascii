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

