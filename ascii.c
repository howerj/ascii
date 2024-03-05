#define ACPU_AUTHOR "Richard James Howe"
#define ACPU_EMAIL  "howe.r.j.89@gmail.com"
#define ACPU_LICENSE "The Unlicense / Public Domain"
#define ACPU_REPO "https://github.com/howerj/ascii"
#define ACPU_PROJECT "A VM with an ASCII based instruction set"
/* This project could be turned into a library (perhaps
 * header-only), for little gain. Many things would need
 * to be renamed, especially the single or double letter
 * functions and types, which would mean the program would lose
 * some of its charm. */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t b;
typedef uint16_t w;
typedef int16_t sw;

#define ACPU_LENGTH (65535)
#define DEFS   (0xD000)
#define RSTART (0xE000)
#define REND   (0xEFF0)
#define VSTART (0xF000)
#define VEND   (0xFFF0)
#define PROGEND (VSTART - 2)
#define NELEMS(X) (sizeof((X)) / sizeof ((X)[0]))

#ifndef ACPU_ASCII_STORAGE
#define ACPU_ASCII_STORAGE (1)
#endif

#ifndef ACPU_UNIT_TESTS
#define ACPU_UNIT_TESTS (1)
#endif

#if ACPU_ASCII_STORAGE != 0
#define WHSIZE (sizeof(w) * 2)
#define BHSIZE (sizeof(b) * 2)
#else
#define WHSIZE (sizeof(w))
#define BHSIZE (sizeof(b))
#endif

struct acpu;
typedef struct acpu acpu_t;

typedef struct {
	int (*get)(void *in);          /* return negative on error, a byte (0-255) otherwise */
	int (*put)(int ch, void *out); /* return ch on no error */
	void *in, *out;                /* passed to 'get' and 'put' respectively */
	size_t read, wrote;            /* read only, bytes 'get' and 'put' respectively */
} io_t; /**< I/O abstraction, use to redirect to wherever you want... */

typedef struct {
	unsigned char *b;
	size_t used, length;
} buffer_t;

struct acpu {
	b m[ACPU_LENGTH];
	w pc, tos, sp, rp;
	b *defs;
	FILE *prog, *debug;
	io_t io;
	int error, initialized;
	int (*user)(acpu_t *a, void *user_param);
	void *user_param;
};

enum {
	E_NONE    =  0,
	E_GENERAL = -1,
	E_INIT    = -2,
	E_BOUND   = -3,
	E_IO      = -4,
	E_CALL    = -5,
	E_DIV0    = -6,
	E_SYNTAX  = -7,
};

static inline w B(w x) { return x % ACPU_LENGTH; }

static int buffer_get(void *in) {
	buffer_t *b = in;
	assert(b);
	assert(b->b);
	if (b->used >= b->length)
		return -1;
	return b->b[b->used++];
}

static int buffer_put(const int ch, void *out) {
	buffer_t *b = out;
	assert(b);
	assert(b->b);
	if (b->used >= b->length)
		return -1;
	return b->b[b->used++] = ch;
}

static int file_get(void *in) {
	assert(in);
	return fgetc((FILE*)in);
}

static int file_put(int ch, void *out) {
	assert(out);
	return fputc(ch, (FILE*)out);
}

static int io_get(io_t *io) {
	assert(io);
	const int r = io->get(io->in);
	io->read += r >= 0;
	assert(r <= 255);
	return r;
}

static int io_put(const int ch, io_t *io) {
	assert(io);
	const int r = io->put(ch, io->out);
	io->wrote += r >= 0;
	assert(r <= 255);
	return r;
}

static uint8_t to(uint8_t v) { assert(v <= 15); return "0123456789ABCDEF"[v & 15]; }

static uint8_t from(uint8_t ch) { 
	assert((ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 70)); /* could set error in acpu_t instead */
	return ch <= 57 ? ch - 48 : ch - 55 ; 
}

static int within(long v, long lo, long hi) {
	return v >= lo && v < hi;
}

static w loadw(acpu_t *a, b *m) {
	assert(a);
	assert(m);
	assert((m >= a->m) && m <= (a->m + ACPU_LENGTH - WHSIZE));
	if (!ACPU_ASCII_STORAGE) {
		w r = 0;
		r = ((w)m[1]) << 0 | ((w)m[0] << 8);
		return r;
	}
	w r = 0;
	r = r | ((w)from(m[3]) <<  0); /* could make endianess compile time option */
	r = r | ((w)from(m[2]) <<  4);
	r = r | ((w)from(m[1]) <<  8);
	r = r | ((w)from(m[0]) << 12);
	return r;
}

static void storew(acpu_t *a, b *m, w v) {
	assert(a);
	assert(m);
	assert((m >= a->m) && m <= (a->m + ACPU_LENGTH - WHSIZE));
	if (!ACPU_ASCII_STORAGE) {
		m[1] = v;
		m[0] = v >> 8;
		return;
	}
	m[3] = to((v >>  0) & 15);
	m[2] = to((v >>  4) & 15);
	m[1] = to((v >>  8) & 15);
	m[0] = to((v >> 12) & 15);
}

static b loadb(acpu_t *a, b *m) {
	assert(a);
	assert(m);
	if (!ACPU_ASCII_STORAGE) {
		return m[0];
	}
	b r = 0;
	r = r | (from(m[1]) << 0);
	r = r | (from(m[0]) << 4);
	return r;
}

static void storeb(acpu_t *a, b *m, w v) {
	assert(a);
	assert(m);
	if (!ACPU_ASCII_STORAGE) {
		m[0] = v;
		return;
	}
	m[1] = to((v >> 0) & 15);
	m[0] = to((v >> 4) & 15);
}

static int stk(acpu_t *a, long sp, long start, long end) {
	assert(a);
	if (!within(sp, start, end)) {
		a->error = E_BOUND;
		return -1;
	}
	return 0;
}

static w pop(acpu_t *a) {
	assert(a);
	if (stk(a, a->sp, VSTART + WHSIZE, VEND))
		return 0;
	w r = loadw(a, &a->m[a->sp]);
	a->sp -= WHSIZE;
	return r;
}

static void push(acpu_t *a, w v) {
	assert(a);
	if (stk(a, a->sp, VSTART, VEND - WHSIZE))
		return;
	a->sp += WHSIZE;
	storew(a, &a->m[a->sp], v);
}

static w rpop(acpu_t *a) {
	assert(a);
	if (stk(a, a->rp, RSTART + WHSIZE, REND))
		return 0;
	w r = loadw(a, &a->m[a->rp]);
	a->rp -= WHSIZE;
	return r;
}

static w rpeek(acpu_t *a) {
	assert(a);
	if (stk(a, a->rp, RSTART + WHSIZE, REND))
		return 0;
	return loadw(a, &a->m[a->rp]);
}

static void rpush(acpu_t *a, w v) {
	assert(a);
	if (stk(a, a->rp, RSTART, REND - WHSIZE))
		return;
	a->rp += WHSIZE;
	storew(a, &a->m[a->rp], v);
}

static int put(acpu_t *a, int ch) {
	assert(a);
	assert(a->io.out);
	if (io_put(ch & 255, &a->io) < 0) {
		a->error = E_IO;
		return -1;
	}
	return 0;
}

static int graphic(int ch) {
	return ch > 32 && ch < 127 ? ch : '.';
}

static int init(acpu_t *a) {
	assert(a);
	if (a->initialized)
		return 0;
	if (!a->defs)
		a->defs = &a->m[DEFS];
	if (!a->sp)
		a->sp = VSTART;
	if (!a->rp)
		a->rp = RSTART;
	for (size_t i = 0; i < (ACPU_LENGTH - DEFS); i++)
		if (a->m[i] == '\0')
			a->m[i] = ' ';
	for (size_t i = DEFS; i < ACPU_LENGTH; i++)
		a->m[i] = '0';
	a->initialized = 1;
	return 0;
}

/* Possible improvements; more documentation, timer, sleep, random numbers,
 * test programs (bootloader, a Forth interpreter written in this ASCII
 * language, hexdump, utilities, program monitor, command line interpreter,
 * rewrite complex instructions in terms of simpler ones and execute that), 
 * "if...else...then" statements (perhaps using '[' and ']'), a comment
 * instruction, string handling instructions, better bounds checking and 
 * more tests, turn this program into a C library, debugging and tracing,
 * run for X cycles, non-blocking input/output options, and more! */
static int acpu(acpu_t *a) {
	assert(a);
	w pc = a->pc, tos = a->tos;
	b *m = a->m;
	if (init(a) < 0)
		return -1;
	assert((a->defs) >= m && (a->defs <= (m + ACPU_LENGTH)));
	for (;!(a->error);) { /* N.B. Some commands do not work when reading from `a->prog` */
		const int ch = a->prog ? fgetc(a->prog) : m[B(pc++)];
		if (ch < 0)
			break;
		if (a->debug) {
			if (fprintf(a->debug, "%04X:%02X/%c\n", a->prog ? -1 : pc - 1, ch, graphic(ch)) < 0) {
				a->error = E_IO;
				goto halt;
			}
		}

		switch (ch) {
		case '$': push(a, tos); tos = 0; break;
		case '0': case '1': case '2': case '3': 
		case '4': case '5': case '6': case '7': 
		case '8': case '9': case 'A': case 'B': 
		case 'C': case 'D': case 'E': case 'F':
			tos <<= 4;
			tos |= from(ch);
			break;

		case '<': tos = -!!((sw)tos < (sw)pop(a)); break;
		case '>': tos = -!!((sw)tos > (sw)pop(a)); break;
		case 'u': tos = -!!(tos < pop(a)); break;
		case 'U': tos = -!!(tos > pop(a)); break;
		case '=': tos = -!!(tos == pop(a)); break;
		case '#': tos = -!!(tos != pop(a)); break;
		case '^': tos = tos ^ pop(a); break;
		case '&': tos = tos & pop(a); break;
		case '|': tos = tos | pop(a); break;
		case '/': { a->error = tos ? a->error: E_DIV0; w r = tos ? tos : 1, t = pop(a); tos = t / r; push(a, t % r); } break;
		case '*': tos = tos * pop(a); break;
		case '+': tos = tos + pop(a); break;
		case '-': tos = pop(a) - tos; break;
		case 'l': tos = pop(a) << tos; break;
		case 'L': tos = pop(a) >> tos; break;
		case '~': tos = ~tos; break;
		case '_': tos = -tos; break;

		case '@': tos = loadw(a, &m[B(tos)]); break;
		case '!': storew(a, &m[B(tos)], pop(a)); tos = pop(a); break;
		case 'K': tos = a->m[B(tos)]; break;
		case 'k': a->m[B(tos)] = pop(a); tos = pop(a); break;
		case 'y': tos = loadb(a, &m[tos]); break;
		case 'Y': storeb(a, &m[B(tos)], pop(a)); tos = pop(a); break;
		case '`': push(a, tos); tos = m[B(pc++)]; break;

		case 's': push(a, tos); break; /* dup */
		case 'S': tos = pop(a); break; /* drop */
		case 'd': { w t = tos; tos = pop(a); push(a, t); }break; /* swap */
		case 'r': push(a, tos); tos = rpop(a); break; /* r> */
		case 'R': rpush(a, tos); tos = pop(a); break; /* >r */
		case 'v': push(a, tos); tos = a->sp; break;
		case 'V': a->sp = pop(a); break;
		case 'p': push(a, tos); tos = a->rp; break;
		case 'P': a->rp = tos; tos = pop(a); break;
		case 'a': push(a, tos); tos = rpeek(a); break;

		/* An `if...else...` construction would be helpful, as would
		 * a loop that executed for `x` cycles. Relative jumps could
		 * also be helpful in hand assembling things. */
		case 'g': rpush(a, pc + WHSIZE); pc = loadw(a, &m[B(pc)]); break;
		case 'G': rpush(a, pc); pc = tos; tos = pop(a); break; /* call */
		case 'j': pc = loadw(a, &m[B(pc)]); break; /* jump */
		case 'J': pc = tos; tos = pop(a); break; /* jump */
		case 'z': if (!tos) { pc = loadw(a, &m[B(pc)]); } else { pc += WHSIZE; } tos = pop(a); break; /* jump on zero */
		case 'Z': if (tos) { pc = loadw(a, &m[B(pc)]); } else { pc += WHSIZE; } tos = pop(a); break; /* jump on non-zero */

		case ';': pc = rpop(a); break; /* end define / return */
		case '%': rpush(a, pc + 1); pc = loadw(a, a->defs + (m[B(pc)] * WHSIZE)); break; /* call definition */
		case '\'': push(a, tos); tos = loadw(a, a->defs + (m[B(pc)] * WHSIZE)); pc++; break;

		case '(': rpush(a, pc); break; /* unconditional jump; push return loc */
		case ')': pc = rpeek(a); break;
		case '{': rpush(a, pc); break; /* conditional jump; push return loc, check tos */
		case '}': if (tos) { pc = rpeek(a); } else { (void)rpop(a); } tos = pop(a); break;

		case 'I': push(a, tos); tos = a->io.get ? io_get(&a->io) : -1; break; /* input */
		case 'O': tos = a->io.put ? io_put(tos & 255, &a->io) : -1; break; /* output */
		case 'o': if (a->io.put) { (void)io_put(tos & 255, &a->io); } tos = pop(a); break;
		case '\0': case 'q': goto halt;
		/* Unused but potentially useful: ,[]" and some alpha chars */
		default: /* nop */ break;

		/* Complex commands; (more) difficult to implement in hardware, 
		 * these could be made to be optional. Another possibility would 
		 * be to replace these commands with code instead.
		 *
		 * A way of querying the system for its properties would be
		 * nice as well.  */
		case '.':
			put(a, to((tos >> 12) & 15));
			put(a, to((tos >>  8) & 15));
			put(a, to((tos >>  4) & 15));
			put(a, to((tos >>  0) & 15));
			tos = pop(a);
			break;
		case ':':
			storew(a, a->defs + (m[B(pc)] * WHSIZE), pc + 1);
			for (pc += 1;;pc++)
				if (m[B(pc)] == ';' || m[B(pc)] == ':')
					break;
			if (m[pc] != ';')
				a->error = E_SYNTAX;
			pc++;
			break; 
		case '?': 
			  if (!a->user) { a->error = E_CALL; break; }
			  a->pc = pc;
			  a->tos = tos;
			  if (a->user(a, a->user_param) < 0) { a->error = E_CALL; break; }
			  tos = a->tos;
			  pc = a->pc;
			  break; /* call user defined extension function */
		}
	}
halt:
	a->pc = pc;
	a->tos = tos;
	return a->error ? -1 : 0;
}

static int eval(const char *prog, const char *in, size_t inlen, char *out, size_t *outlen) {
	assert(prog);
	assert(in);
	assert(out);
	acpu_t a = { .pc = 0, };
	buffer_t inb = { .b = (unsigned char*)in, .length = inlen, };
	buffer_t oub = { .b = (unsigned char*)out, .length = *outlen, };
	a.io = (io_t){ .get = buffer_get, .put = buffer_put, .in = &inb, .out = &oub, };
	*outlen = 0;
	const size_t length = strlen(prog);
	if (length > ACPU_LENGTH)
		return -1;
	memcpy(a.m, prog, length);
	const int r = acpu(&a);
	*outlen = oub.used;
	return r;
}

static int acpu_tests(void) {
	if (!ACPU_UNIT_TESTS)
		return 0;
	/* This code is compiled out if ACPU_UNIT_TESTS == 0 */
	typedef struct {
		int r;
		const char *program;
		const char *expect;
		const char *input;
	} test_t;

	/* TODO: Test all these:
	'<', '>', 'u', 'U', '^', '/', '*', '-', 'l', 'L',
	'K', 'k', 'y', 'Y', 's', 'd', 'r', 'R', 'v', 'V',
	'p', 'P', 'a', 'g', 'G', 'z', 'Z', */
	test_t tests[] = { /* '(' and ')' are infinite loops so cannot be tested... */
		{ 0, "", "", "", },
		{ 0, "$1", "", "", },
		{ 0, "$12345", "", "", },
		{ 0, "$1$2+.", "0003", "", },
		{ 0, "$1$2=.", "0000", "", },
		{ 0, "$1$2|.", "0003", "", },
		{ 0, "$1$2#.", "FFFF", "", },
		{ 0, "$1$2#_.", "0001", "", },
		{ 0, "$ABCD$0000&.", "0000", "", },
		{ 0, "$FFFF$F05A&.", "F05A", "", },
		{ 0, "$FFFF$F05A^.", "0FA5", "", },
		{ -1, ".", "0000", "", },
		{ 0, "$5{s.$1-s}", "00050004000300020001", "", },
		{ -1, "{}", "", "", },
		{ 0, "IO", "X", "X", },
		{ 0, "IOIO", "XY", "XY", },
		{ 0, "IOqIO", "X", "XY", },
		{ 0, "IOIOIIOSO", "ABDC", "ABCDEF", },
		{ 0, ":A $3 $4 + . ;%A%A", "00070007", "" },
		{ 0, "$6789.:A $2 $3 + ;%A%A+$A=.", "6789FFFF", "" },
		{ 0, "$E123$2000!$2$2+.$2000@.", "0004E123", "" },
		{ 0, "$F05A~", "", "", },
		{ 0, "$F05A~.", "0FA5", "", },
		{ 0, "`Ho`io`!o", "Hi!", "", },
		{ 0, "`Ao`Bo", "AB", "", },
		{ 0, "j0008`Ao`Bo", "B", "", },
		{ 0, "$6J`Ao`Bo", "B", "", },
		{ 0, " $7J`Ao`Bo", "B", "", },
		{ 0, "$1$2..", "00020001", "", },
		{ 0, "$1$2d..", "00010002", "", },
		{ 0, "$1z0000", "", "", },
	};

	for (size_t i = 0; i < NELEMS(tests); i++) {
		test_t *t = &tests[i];
		char inb[64] = { 0, }, outb[64] = { 0, };
		size_t outblen = sizeof (outb) - 1;
		assert(strlen(t->input) < (sizeof (inb) - 1));
		strcpy(inb, t->input);
		const int r = eval(t->program, inb, sizeof (inb), outb, &outblen);
		if (r != t->r)
			return -1;
		if (outblen >= (sizeof(outb) - 1))
			return -1;
		if (strcmp(t->expect, outb))
			return -1;
	}
	return 0;
}

static int help(FILE *out, const char *arg0) {
	assert(out);
	assert(arg0);
	const char *fmt ="\
Usage: %s [file|string|tests|f|s|t] input \n\n\
Project: " ACPU_PROJECT "\n\
Author:  " ACPU_AUTHOR "\n\
License: " ACPU_LICENSE "\n\
Email:   " ACPU_EMAIL "\n\
Repo:    " ACPU_REPO "\n\n\
This program returns non-zero on error. Built in self tests\n\
are run at startup. For a more detailed help - use the source.\n\n";
	return fprintf(out, fmt, arg0);
}

int main(int argc, char **argv) {
	static acpu_t a = { .pc = 0, };
	a.io = (io_t){ .in = stdin, .out = stdout, .put = file_put, .get = file_get, };
	a.debug = getenv("DEBUG") ? stderr : NULL;
	/*a.prog = stdin;*/
	if (argc < 2) {
		(void)help(stderr, argv[0]);
		return 1;
	}
	const char *select = argv[1], *input = argv[2];
	if (argc > 2 && (!strcmp(select, "file") || !strcmp(select, "f"))) {
		FILE *in = fopen(input, "rb");
		if (!in) {
			(void)fprintf(stderr, "Unable to open file `%s` for reading: %s\n", input, strerror(errno));
			return 1;
		}
		if (fread(a.m, 1, PROGEND, in)) { /* nothing */ }
		if (fclose(in) < 0)
			return 1;
	} else if (argc > 2 && (!strcmp(select, "string") || !strcmp(select, "s"))) {
		size_t l = strlen(input);
		l = l > PROGEND ? PROGEND : l;
		memcpy(a.m, input, l);
	} else if (!strcmp(select, "test") || !strcmp(select, "tests") || !strcmp(select, "t")) {
		return acpu_tests() < 0;
	} else {
		(void)help(stderr, argv[0]);
		return 1;
	}
	return acpu(&a) < 0;
}
