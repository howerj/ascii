#define ACPU_AUTHOR "Richard James Howe"
#define ACPU_EMAIL  "howe.r.j.89@gmail.com"
#define ACPU_LICENSE "The Unlicense / Public Domain"
#define ACPU_REPO "https://github.com/howerj/ascii"
#define ACPU_PROJECT "A VM with an ASCII based instruction set"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
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
	FILE *prog;
	io_t io;
	int error;
	int (*user)(acpu_t *a, void *user_param);
	void *user_param;
};

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
	assert((ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 70));
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
		r = ((w)m[0]) << 0 | ((w)m[1] << 8);
		return r;
	}
	w r = 0;
	r = r | ((w)from(m[0]) <<  0);
	r = r | ((w)from(m[1]) <<  4);
	r = r | ((w)from(m[2]) <<  8);
	r = r | ((w)from(m[3]) << 12);
	return r;
}

static void storew(acpu_t *a, b *m, w v) {
	assert(a);
	assert(m);
	assert((m >= a->m) && m <= (a->m + ACPU_LENGTH - WHSIZE));
	if (!ACPU_ASCII_STORAGE) {
		m[0] = v;
		m[1] = v >> 8;
		return;
	}
	m[0] = to((v >>  0) & 15);
	m[1] = to((v >>  4) & 15);
	m[2] = to((v >>  8) & 15);
	m[3] = to((v >> 12) & 15);
}

static b loadb(acpu_t *a, b *m) {
	assert(a);
	assert(m);
	if (!ACPU_ASCII_STORAGE) {
		return m[0];
	}
	b r = 0;
	r = r | (from(m[0]) << 0);
	r = r | (from(m[1]) << 4);
	return r;
}

static void storeb(acpu_t *a, b *m, w v) {
	assert(a);
	assert(m);
	if (!ACPU_ASCII_STORAGE) {
		m[0] = v;
		return;
	}
	m[0] = to((v >> 0) & 15);
	m[1] = to((v >> 4) & 15);
}

static int stk(acpu_t *a, long sp, long start, long end) {
	assert(a);
	if (!within(sp, start, end)) {
		a->error = 1;
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
		a->error = 1;
		return -1;
	}
	return 0;
}

/* TODO: Make short program to assembly, hexdump, disassembly to memory as a
 * simple bootloader.
 * TODO: Documentation
 * TODO: Unit Tests, Test suite of programs, make a Forth interpreter...
 * TODO: Turn into library (header only?)
 * TODO: Optional: commands, load/store ASCII HEX, ...
 * TODO: Replace more complex instructions with code?
 * TODO: Bounds checking
 * TODO: Error codes (set a->error to Error code) */
static int acpu(acpu_t *a) {
	assert(a);
	w pc = a->pc, tos = a->tos;
	b *m = a->m;
	if (!a->defs)
		a->defs = &m[DEFS];
	if (!a->sp)
		a->sp = VSTART;
	if (!a->rp)
		a->rp = RSTART;
	assert((a->defs) >= m && (a->defs <= (m + ACPU_LENGTH)));
	for (;!(a->error);) { /* N.B. Some commands do not work when reading from `a->prog` */
		const int ch = a->prog ? fgetc(a->prog) : m[pc++];
		if (ch < 0)
			break;
		switch (ch) {
		case '$': push(a, tos); tos = 0; break;
		case '0': case '1': case '2': case '3': 
		case '4': case '5': case '6': case '7': 
		case '8': case '9': case 'A': case 'B': 
		case 'C': case 'D': case 'E': case 'F':
			tos <<= 4;
			tos |= from(ch);
			break;
		case '.':
			put(a, to((tos >> 12) & 15));
			put(a, to((tos >>  8) & 15));
			put(a, to((tos >>  4) & 15));
			put(a, to((tos >>  0) & 15));
			tos = pop(a);
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
		case '/': { w r = tos ? tos : 1, t = pop(a); tos = t / r; push(a, t % r); } break;
		case '*': tos = tos * pop(a); break;
		case '+': tos = tos + pop(a); break;
		case '-': tos = pop(a) - tos; break;
		case 'l': tos = pop(a) << tos; break;
		case 'L': tos = pop(a) >> tos; break;
		case '~': tos = ~tos; break;
		case '_': tos = -tos; break;

		case '@': tos = loadw(a, &m[tos]); break;
		case '!': storew(a, &m[tos], pop(a)); tos = pop(a); break;
		case 'K': tos = a->m[tos]; break;
		case 'k': a->m[tos] = pop(a); break;
		case '`': push(a, tos); tos = m[pc++]; break;

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

		case 'g': rpush(a, pc + WHSIZE); pc = loadw(a, &m[pc]); break;
		case 'G': rpush(a, pc); pc = tos; tos = pop(a); break; /* call */
		case 'x': pc = rpop(a); break; /* return */
		case 'j': pc = loadw(a, &m[pc]); break; /* jump */
		case 'J': pc = tos; tos = pop(a); break; /* jump */
		case 'z': if (!tos) { pc = loadw(a, &m[pc]); } else { pc += WHSIZE; } break; /* jump on zero */
		case 'Z': if (tos) { pc = loadw(a, &m[pc]); } else { pc += WHSIZE; } break; /* jump on non-zero */
		case ':':
			storew(a, a->defs + (m[pc] * WHSIZE), pc + 1);
			for (pc += 1;;pc++)
				if (m[pc] == ';' || m[pc] == ':')
					break;
			if (m[pc] != ';')
				a->error = -1;
			pc++;
			break; 
		case ';': pc = rpop(a); break; /* end define */
		case '%': rpush(a, pc + 1); pc = loadw(a, a->defs + (m[pc] * WHSIZE)); break; /* call definition */
		case '?': 
			  if (!a->user) { a->error = 1; break; }
			  a->pc = pc;
			  a->tos = tos;
			  if (a->user(a, a->user_param) < 0) { a->error = 1; break; }
			  tos = a->tos;
			  pc = a->pc;
			  break; /* call user defined extension function */
		case '(': rpush(a, pc); break; /* unconditional jump; push return loc */
		case ')': pc = rpeek(a); break;
		case '{': rpush(a, pc); break; /* conditional jump; push return loc, check tos */
		case '}': if (tos) { pc = rpeek(a); } else { (void)rpop(a); } tos = pop(a); break;
 
		case 'I': push(a, tos); tos = a->io.get ? io_get(&a->io) : -1; break; /* input */
		case 'O': tos = a->io.put ? io_put(tos & 255, &a->io) : -1; break; /* output */

		case '\0': case 'q': goto halt;
		default: /* nop */ break;
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

static int test(FILE *in, FILE *out) {
	assert(in);
	assert(out);
	if (!ACPU_UNIT_TESTS)
		return 0;
	/* This code is compiled out if ACPU_UNIT_TESTS == 0 */
	typedef struct {
		int r;
		const char *program;
		const char *expect;
		const char *input;
	} test_t;

	test_t tests[] = {
		{ 0, "$1$2+.", "0003", "", },
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
Usage: %s [file|string|f|s] input \n\n\
Project: " ACPU_PROJECT "\n\
Author:  " ACPU_AUTHOR "\n\
License: " ACPU_LICENSE "\n\
Email:   " ACPU_EMAIL "\n\
Repo:    " ACPU_REPO "\n\n\
This program returns non-zero on error.\n\n";
	return fprintf(out, fmt, arg0);
}

int main(int argc, char **argv) {
	static acpu_t a = { .pc = 0, };
	a.io = (io_t){ .in = stdin, .out = stdout, .put = file_put, .get = file_get, };
	/*a.prog = stdin;*/
	if (test(stdin, stdout) < 0)
		return 1;
	if (argc < 3) {
		(void)help(stderr, argv[0]);
		return 1;
	}
	const char *select = argv[1], *input = argv[2];
	if (!strcmp(select, "file") || !strcmp(select, "f")) {
		FILE *in = fopen(input, "rb");
		if (!in) {
			(void)fprintf(stderr, "Unable to open file `%s` for reading: %s\n", input, strerror(errno));
			return 1;
		}
		if (fread(a.m, 1, PROGEND, in)) { /* nothing */ }
		if (fclose(in) < 0)
			return 1;
	} else if (!strcmp(select, "string") || !strcmp(select, "s")) {
		size_t l = strlen(input);
		l = l > PROGEND ? PROGEND : l;
		memcpy(a.m, input, l);
	} else {
		(void)help(stderr, argv[0]);
		return 1;
	}
	return acpu(&a) < 0;
}
