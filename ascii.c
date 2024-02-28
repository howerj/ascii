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

#define LENGTH (65535)
#define DEFS   (0xD000)
#define RSTART (0xE000)
#define REND   (0xEFF0)
#define VSTART (0xF000)
#define VEND   (0xFFF0)
#define PROGEND (VSTART - 2)

#ifndef ACPU_ASCII_STORAGE
#define ACPU_ASCII_STORAGE (1)
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

struct acpu {
	b m[LENGTH];
	w pc, tos, sp, rp;
	w defs[256];
	FILE *prog, *in, *out;
	int error;
	int (*user)(acpu_t *a, void *user_param);
	void *user_param;
};

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
	assert((m >= a->m) && m <= (a->m + LENGTH - WHSIZE));
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
	assert((m >= a->m) && m <= (a->m + LENGTH - WHSIZE));
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
	assert(a->out);
	if (fputc(ch & 255, a->out) < 0) {
		a->error = 1;
		return -1;
	}
	return 0;
}

/* TODO: Make short program to assembly, hexdump, disassembly to memory as a
 * simple bootloader.
 * TODO: Documentation
 * TODO: Test suite of programs, make a Forth interpreter...
 * TODO: Unit tests
 * TODO: Abstract out I/O
 * TODO: Turn into library (header only?)
 * TODO: Optional: commands, load/store ASCII HEX, ...
 * TODO: Replace more complex instructions with code?
 * TODO: Put defs lookup table in main memory
 * TODO: Bounds checking, fault handling, etcetera. */
static int acpu(acpu_t *a) {
	assert(a);
	w pc = a->pc, tos = a->tos;
	b *m = a->m;
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
			a->defs[m[pc]] = pc + 1; /* define */
			for (pc += 1;;pc++)
				if (m[pc] == ';' || m[pc] == ':')
					break;
			if (m[pc] != ';')
				a->error = -1;
			pc++;
			break; 
		case ';': pc = rpop(a); break; /* end define */
		case '%': rpush(a, pc + 1); pc = a->defs[m[pc]]; break; /* call definition */
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
 
		case 'I': push(a, tos); tos = a->in ? fgetc(a->in) : -1; break; /* input */
		case 'O': tos = a->out ? fputc(tos & 255, a->out) : -1; break; /* output */

		case '\0': case 'q': goto halt;
		default: /* nop */ break;
		}

	}
halt:
	a->pc = pc;
	a->tos = tos;
	return a->error ? -1 : 0;
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
	a.sp = VSTART;
	a.rp = RSTART;
	a.in = stdin;
	a.out = stdout;
	/*a.prog = stdin;*/
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
