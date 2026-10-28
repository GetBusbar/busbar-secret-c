/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors
 *
 * busbar-secret-c: a busbar SECRET plugin written in C from the generated header ALONE. It
 * includes busbar_plugin.h and nothing else: no Rust, no busbar crate, no libc header, no
 * allocator. busbar's plugin-ci.yml compiles it with the system C compiler against the header at
 * this repo's busbar pin and loads the library through the loader's dropped-in path
 * (`load_dropped`), then drives the secret kind's conformance script over it.
 *
 * What it serves: named secrets whose material is written in its own settings.
 *
 *   settings          {"values": {"<name>": "<material>", ...}}
 *   resolve settings  {"name": "<name>"}
 *
 * Per op of the secret table:
 *   validate / open / refresh  the settings must be one JSON object whose one setting is `values`,
 *                              an object of non-empty strings of at most MATERIAL_CAP bytes each;
 *                              anything else FAILS naming why, the same at all three. `open` keeps
 *                              a copy of the settings (at most SETTINGS_CAP bytes); `refresh`
 *                              replaces it.
 *   resolve   READY with the material under a lease (octets, flagged secret); a name it does not
 *             hold FAILS with NOT_FOUND; a resolve settings blob that is not {"name": "<non-empty
 *             string>"} (another setting included) FAILS with INVALID; an empty material FAILS
 *             with INVALID.
 *   release   READY for an outstanding lease (its material is zeroed), REFUSED for any other.
 *   check     REFUSED ("not served"): resolve judges every reference.
 *   close     every outstanding lease is zeroed; the instance is gone.
 *   the rest of the lifecycle answers READY.
 *
 * BUSBAR_PLUGIN_KIND_ABI (default BB_SECRET_ABI_VERSION) is the kind ABI the door and its
 * Statement state. busbar's C conformance builds this source again with another value: the
 * loader must refuse that build.
 *
 * At most one instance (MARK_ONE_INSTANCE): its state is static, and every op that reads or writes
 * it (open, refresh, resolve, release, close) holds the instance lock, so a `refresh` the host runs
 * beside a `resolve` never lets it read half-replaced settings. The lock is a ticket lock on C11
 * `_Atomic` counters (a language feature: no header, no libc).
 */
#include "busbar_plugin.h"

#if defined(__STDC_NO_ATOMICS__)
#error "busbar-secret-c needs C11 _Atomic for its instance lock"
#endif

#ifndef BUSBAR_PLUGIN_KIND_ABI
#define BUSBAR_PLUGIN_KIND_ABI BB_SECRET_ABI_VERSION
#endif

#if defined(_WIN32)
#define DOOR_EXPORT __declspec(dllexport)
#else
#define DOOR_EXPORT __attribute__((visibility("default")))
#endif

#define STR(s) { (const uint8_t *)(s), sizeof(s) - 1 }

/* The largest settings blob `open` keeps, the largest material one lease holds, and how many
 * leases may be outstanding at once. */
#define SETTINGS_CAP 8192
#define MATERIAL_CAP 1024
#define LEASES 16
/* The deepest JSON nesting the scanner follows. */
#define DEPTH_CAP 32

/* ---- the Statement ---- */

static const bb_mech_Statement STATEMENT = {
    .size = (uint32_t)sizeof(bb_mech_Statement),
    .kind = (uint32_t)BB_MECH_KindCode_Secret,
    .kind_abi = BUSBAR_PLUGIN_KIND_ABI,
    .max_inflight = 1,
    .name = STR("busbar-secret-c"),
    .version = STR("1.6.0"),
    .marks = BB_MECH_MARK_ONE_INSTANCE,
};

/* ---- the one instance ---- */

struct lease {
    uint64_t id; /* 0 = free */
    size_t len;
    uint8_t material[MATERIAL_CAP];
};

struct instance {
    int open;
    size_t settings_len;
    uint8_t settings[SETTINGS_CAP];
    uint64_t next_lease;
    struct lease leases[LEASES];
};

static struct instance THE_INSTANCE;

/* THE instance lock: a ticket lock. `++` on an `_Atomic` object is one atomic read-modify-write
 * and a read of one is an atomic load (C11 6.5.2.4, 6.2.6.1), both sequentially consistent. */
static _Atomic unsigned long NEXT_TICKET;
static _Atomic unsigned long SERVING;

static void lock(void) {
    unsigned long mine = NEXT_TICKET++;
    while (SERVING != mine) {
    }
}

static void unlock(void) {
    SERVING++;
}

/* ---- helpers: no libc ---- */

static void zero(volatile uint8_t *p, size_t n) {
    while (n--) {
        *p++ = 0;
    }
}

static size_t length(const char *text) {
    size_t n = 0;
    while (text[n]) {
        n++;
    }
    return n;
}

/* Answer `outcome`: the plugin writes back its own `out` size (never more than the host's) and
 * mirrors the outcome it returns. */
static bb_mech_RawOutcome answer(bb_mech_OutHead *head, size_t own, bb_mech_Outcome outcome) {
    if (head->size > own) {
        head->size = (uint32_t)own;
    }
    head->outcome = (bb_mech_RawOutcome)outcome;
    return (bb_mech_RawOutcome)outcome;
}

/* A FAILED or REFUSED answer naming `text` (static) in `head.error`. */
static bb_mech_RawOutcome say(bb_mech_OutHead *head, size_t own, bb_mech_Outcome outcome,
                              const char *text) {
    head->error.ptr = (const uint8_t *)text;
    head->error.len = length(text);
    return answer(head, own, outcome);
}

/* Copy `text` into a lent buffer of `cap` bytes; answers how many bytes were written. */
static size_t lend(uint8_t *buf, size_t cap, const char *text) {
    size_t n = 0;
    if (buf == 0) {
        return 0;
    }
    while (text[n] && n < cap) {
        buf[n] = (uint8_t)text[n];
        n++;
    }
    return n;
}

/* ---- a JSON scanner: just enough to read the two settings shapes, and to refuse the rest ---- */

struct cursor {
    const uint8_t *p;
    const uint8_t *end;
};

static void ws(struct cursor *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) {
        c->p++;
    }
}

static int hex(uint8_t h) {
    if (h >= '0' && h <= '9') return h - '0';
    if (h >= 'a' && h <= 'f') return h - 'a' + 10;
    if (h >= 'A' && h <= 'F') return h - 'A' + 10;
    return -1;
}

/* One JSON string at the cursor, decoded into `out` (`cap` bytes; `out` may be 0 to only scan).
 * Answers 1 and the decoded length in `*len`, or 0 when it is not a well-formed string or does not
 * fit. \u escapes decode to UTF-8 within the Basic Multilingual Plane; a surrogate is refused. */
static int string(struct cursor *c, uint8_t *out, size_t cap, size_t *len) {
    size_t n = 0;
    if (c->p >= c->end || *c->p != '"') {
        return 0;
    }
    c->p++;
    while (c->p < c->end) {
        uint8_t b = *c->p++;
        uint32_t cp;
        uint8_t enc[3];
        size_t k, m;
        if (b == '"') {
            *len = n;
            return 1;
        }
        if (b < 0x20) {
            return 0;
        }
        if (b != '\\') {
            enc[0] = b;
            m = 1;
        } else {
            if (c->p >= c->end) {
                return 0;
            }
            b = *c->p++;
            m = 1;
            switch (b) {
            case '"': enc[0] = '"'; break;
            case '\\': enc[0] = '\\'; break;
            case '/': enc[0] = '/'; break;
            case 'b': enc[0] = '\b'; break;
            case 'f': enc[0] = '\f'; break;
            case 'n': enc[0] = '\n'; break;
            case 'r': enc[0] = '\r'; break;
            case 't': enc[0] = '\t'; break;
            case 'u':
                if (c->end - c->p < 4) {
                    return 0;
                }
                cp = 0;
                for (k = 0; k < 4; k++) {
                    int h = hex(c->p[k]);
                    if (h < 0) {
                        return 0;
                    }
                    cp = cp * 16 + (uint32_t)h;
                }
                c->p += 4;
                if (cp >= 0xD800 && cp <= 0xDFFF) {
                    return 0;
                }
                if (cp < 0x80) {
                    enc[0] = (uint8_t)cp;
                } else if (cp < 0x800) {
                    enc[0] = (uint8_t)(0xC0 | (cp >> 6));
                    enc[1] = (uint8_t)(0x80 | (cp & 0x3F));
                    m = 2;
                } else {
                    enc[0] = (uint8_t)(0xE0 | (cp >> 12));
                    enc[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
                    enc[2] = (uint8_t)(0x80 | (cp & 0x3F));
                    m = 3;
                }
                break;
            default:
                return 0;
            }
        }
        for (k = 0; k < m; k++) {
            if (out != 0) {
                if (n >= cap) {
                    return 0;
                }
                out[n] = enc[k];
            }
            n++;
        }
    }
    return 0;
}

static int literal(struct cursor *c, const char *word) {
    size_t n = length(word), k;
    if ((size_t)(c->end - c->p) < n) {
        return 0;
    }
    for (k = 0; k < n; k++) {
        if (c->p[k] != (uint8_t)word[k]) {
            return 0;
        }
    }
    c->p += n;
    return 1;
}

static int digits(struct cursor *c) {
    const uint8_t *from = c->p;
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        c->p++;
    }
    return c->p > from;
}

static int number(struct cursor *c) {
    if (c->p < c->end && *c->p == '-') {
        c->p++;
    }
    if (c->p < c->end && *c->p == '0') {
        c->p++;
    } else if (!digits(c)) {
        return 0;
    }
    if (c->p < c->end && *c->p == '.') {
        c->p++;
        if (!digits(c)) {
            return 0;
        }
    }
    if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
        c->p++;
        if (c->p < c->end && (*c->p == '+' || *c->p == '-')) {
            c->p++;
        }
        if (!digits(c)) {
            return 0;
        }
    }
    return 1;
}

/* Skip one well-formed JSON value at the cursor; answers 0 when there is none. */
static int value(struct cursor *c, int depth) {
    size_t ignored;
    ws(c);
    if (c->p >= c->end || depth > DEPTH_CAP) {
        return 0;
    }
    switch (*c->p) {
    case '"':
        return string(c, 0, 0, &ignored);
    case 't':
        return literal(c, "true");
    case 'f':
        return literal(c, "false");
    case 'n':
        return literal(c, "null");
    case '[':
        c->p++;
        ws(c);
        if (c->p < c->end && *c->p == ']') {
            c->p++;
            return 1;
        }
        for (;;) {
            if (!value(c, depth + 1)) {
                return 0;
            }
            ws(c);
            if (c->p < c->end && *c->p == ',') {
                c->p++;
                continue;
            }
            if (c->p < c->end && *c->p == ']') {
                c->p++;
                return 1;
            }
            return 0;
        }
    case '{':
        c->p++;
        ws(c);
        if (c->p < c->end && *c->p == '}') {
            c->p++;
            return 1;
        }
        for (;;) {
            ws(c);
            if (!string(c, 0, 0, &ignored)) {
                return 0;
            }
            ws(c);
            if (c->p >= c->end || *c->p != ':') {
                return 0;
            }
            c->p++;
            if (!value(c, depth + 1)) {
                return 0;
            }
            ws(c);
            if (c->p < c->end && *c->p == ',') {
                c->p++;
                continue;
            }
            if (c->p < c->end && *c->p == '}') {
                c->p++;
                return 1;
            }
            return 0;
        }
    default:
        return number(c);
    }
}

/* Whether `ptr[0..len]` is exactly one JSON object (nothing but whitespace around it). */
static int one_object(const uint8_t *ptr, size_t len) {
    struct cursor c;
    if (ptr == 0 || len == 0) {
        return 0;
    }
    c.p = ptr;
    c.end = ptr + len;
    ws(&c);
    if (c.p >= c.end || *c.p != '{' || !value(&c, 0)) {
        return 0;
    }
    ws(&c);
    return c.p == c.end;
}

/* Whether the decoded key at the cursor equals `want` (`want_len` bytes); the cursor moves past it.
 * Answers -1 when the key is not a well-formed string. */
static int key_is(struct cursor *c, const uint8_t *want, size_t want_len) {
    uint8_t key[MATERIAL_CAP];
    size_t n;
    struct cursor probe = *c;
    if (!string(&probe, key, sizeof key, &n)) {
        /* Too long to hold: it cannot equal any name this plugin is asked for; skip it. */
        if (!string(c, 0, 0, &n)) {
            return -1;
        }
        return 0;
    }
    *c = probe;
    if (n != want_len) {
        return 0;
    }
    while (n--) {
        if (key[n] != want[n]) {
            return 0;
        }
    }
    return 1;
}

/* Inside a well-formed object (cursor just past its `{`): find member `want` and leave the cursor
 * at its value. Answers 1 when found. */
static int member(struct cursor *c, const char *want_text, const uint8_t *want, size_t want_len) {
    if (want_text != 0) {
        want = (const uint8_t *)want_text;
        want_len = length(want_text);
    }
    ws(c);
    if (c->p < c->end && *c->p == '}') {
        return 0;
    }
    for (;;) {
        int is;
        ws(c);
        is = key_is(c, want, want_len);
        if (is < 0) {
            return 0;
        }
        ws(c);
        c->p++; /* ':' (the object is well formed) */
        ws(c);
        if (is) {
            return 1;
        }
        if (!value(c, 1)) {
            return 0;
        }
        ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        return 0;
    }
}

static const char NOT_AN_OBJECT[] = "settings must be one JSON object";
static const char NO_VALUES[] = "settings: `values` must be an object";
static const char ONLY_VALUES[] = "settings: `values` is the only setting";
static const char NOT_STRINGS[] = "settings: every `values` entry must be a string";
static const char EMPTY_VALUE[] = "settings: a `values` entry is empty; a secret must be non-empty";
static const char VALUE_TOO_LARGE[] =
    "settings: a `values` entry is larger than a lease holds (1024 bytes)";
static const char TOO_LARGE[] = "settings: larger than this plugin keeps";

/* Why the `values` object at the cursor (on its `{`) is not one this plugin serves, or 0; the
 * cursor ends past its `}`. Every entry is judged here, so `resolve` never meets a value it
 * cannot lease: an empty one, or one larger than a lease holds. */
static const char *values_refusal(struct cursor *c) {
    c->p++;
    ws(c);
    if (c->p < c->end && *c->p == '}') {
        c->p++;
        return 0;
    }
    for (;;) {
        size_t n;
        ws(c);
        if (!string(c, 0, 0, &n)) {
            return NOT_STRINGS;
        }
        ws(c);
        c->p++; /* ':' */
        ws(c);
        if (c->p >= c->end || *c->p != '"' || !string(c, 0, 0, &n)) {
            return NOT_STRINGS;
        }
        if (n == 0) {
            return EMPTY_VALUE;
        }
        if (n > MATERIAL_CAP) {
            return VALUE_TOO_LARGE;
        }
        ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        c->p++; /* '}' (the object is well formed) */
        return 0;
    }
}

/* Why `settings` is not this plugin's settings, or 0 when it is: one object whose one setting is
 * `values`; any other setting is refused, never ignored. */
static const char *settings_refusal(const uint8_t *ptr, size_t len) {
    struct cursor c;
    if (len > SETTINGS_CAP) {
        return TOO_LARGE;
    }
    if (!one_object(ptr, len)) {
        return NOT_AN_OBJECT;
    }
    c.p = ptr;
    c.end = ptr + len;
    ws(&c);
    c.p++;
    ws(&c);
    if (c.p < c.end && *c.p == '}') {
        return NO_VALUES;
    }
    for (;;) {
        const char *why;
        ws(&c);
        if (key_is(&c, (const uint8_t *)"values", 6) != 1) {
            return ONLY_VALUES;
        }
        ws(&c);
        c.p++; /* ':' */
        ws(&c);
        if (c.p >= c.end || *c.p != '{') {
            return NO_VALUES;
        }
        why = values_refusal(&c);
        if (why != 0) {
            return why;
        }
        ws(&c);
        if (c.p < c.end && *c.p == ',') {
            c.p++;
            continue;
        }
        return 0;
    }
}

/* Whether every member of the well-formed object `ptr[0..len]` is named `want`. */
static int only_member(const uint8_t *ptr, size_t len, const char *want) {
    struct cursor c;
    c.p = ptr;
    c.end = ptr + len;
    ws(&c);
    c.p++;
    ws(&c);
    if (c.p < c.end && *c.p == '}') {
        return 1;
    }
    for (;;) {
        ws(&c);
        if (key_is(&c, (const uint8_t *)want, length(want)) != 1) {
            return 0;
        }
        ws(&c);
        c.p++; /* ':' */
        if (!value(&c, 1)) {
            return 0;
        }
        ws(&c);
        if (c.p < c.end && *c.p == ',') {
            c.p++;
            continue;
        }
        return 1;
    }
}

/* ---- the lifecycle ---- */

static bb_mech_RawOutcome op_validate(void *inst, const void *in, void *out) {
    const bb_mech_ValidateIn *v = in;
    bb_mech_OutHead *o = out;
    const char *why;
    size_t n;
    (void)inst;
    if (v->head.size < sizeof *v) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "validate: short in");
    }
    why = settings_refusal(v->settings.ptr, v->settings.len);
    if (why == 0) {
        return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
    }
    /* No instance holds the reason past the call: it goes into the host's lent buffer. */
    n = lend(v->err_buf, v->err_cap, why);
    o->error.ptr = v->err_buf;
    o->error.len = n;
    return answer(o, sizeof *o, BB_MECH_Outcome_Failed);
}

/* Keep `settings` as the instance's, or answer why not. */
static const char *keep(struct instance *s, const bb_mech_Blob *settings) {
    const char *why = settings_refusal(settings->ptr, settings->len);
    size_t k;
    if (why != 0) {
        return why;
    }
    zero(s->settings, sizeof s->settings);
    for (k = 0; k < settings->len; k++) {
        s->settings[k] = settings->ptr[k];
    }
    s->settings_len = settings->len;
    return 0;
}

static void drop_leases(struct instance *s) {
    size_t k;
    for (k = 0; k < LEASES; k++) {
        zero(s->leases[k].material, sizeof s->leases[k].material);
        s->leases[k].id = 0;
        s->leases[k].len = 0;
    }
}

static bb_mech_RawOutcome op_open_held(void *inst, const void *in, void *out) {
    const bb_mech_OpenIn *i = in;
    bb_mech_OpenOut *o = out;
    const char *why;
    (void)inst;
    if (i->head.size < sizeof *i || o->head.size < sizeof *o) {
        return say(&o->head, sizeof *o, BB_MECH_Outcome_Refused, "open: short frame");
    }
    if (THE_INSTANCE.open) {
        o->err_len = lend(i->err_buf, i->err_cap, "one instance only");
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    why = keep(&THE_INSTANCE, &i->settings);
    if (why != 0) {
        o->err_len = lend(i->err_buf, i->err_cap, why);
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    drop_leases(&THE_INSTANCE);
    THE_INSTANCE.open = 1;
    THE_INSTANCE.next_lease = 1;
    o->instance = &THE_INSTANCE;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_refresh_held(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_mech_RefreshIn *r = in;
    bb_mech_OutHead *o = out;
    const char *why;
    if (r->head.size < sizeof *r) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "refresh: short in");
    }
    why = keep(s, &r->settings);
    if (why != 0) {
        return say(o, sizeof *o, BB_MECH_Outcome_Failed, why);
    }
    return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_ready(void *inst, const void *in, void *out) {
    (void)inst;
    (void)in;
    return answer(out, sizeof(bb_mech_OutHead), BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_tick(void *inst, const void *in, void *out) {
    bb_mech_TickOut *o = out;
    (void)inst;
    (void)in;
    if (o->head.size >= sizeof *o) {
        o->next_tick_ns = 0;
    }
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_cancel(void *inst, const void *in, void *out) {
    bb_mech_CancelOut *o = out;
    (void)inst;
    (void)in;
    if (o->head.size >= sizeof *o) {
        o->disposition = BB_SECRET_CANCEL_ABORTED;
    }
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_release_held(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_mech_ReleaseIn *r = in;
    bb_mech_OutHead *o = out;
    size_t k;
    if (r->head.size < sizeof *r) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "release: short in");
    }
    if (r->lease != 0) {
        for (k = 0; k < LEASES; k++) {
            if (s->leases[k].id == r->lease) {
                /* The owner zeroises secret material on release (BLOB_SECRET). */
                zero(s->leases[k].material, s->leases[k].len);
                s->leases[k].id = 0;
                s->leases[k].len = 0;
                return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
            }
        }
    }
    return say(o, sizeof *o, BB_MECH_Outcome_Refused, "no such lease");
}

static bb_mech_RawOutcome op_close_held(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    (void)in;
    drop_leases(s);
    zero(s->settings, sizeof s->settings);
    s->settings_len = 0;
    s->open = 0;
    return answer(out, sizeof(bb_mech_OutHead), BB_MECH_Outcome_Ready);
}

/* ---- the secret op ---- */

static bb_mech_RawOutcome resolve_failed(bb_secret_ResolveOut *o, uint32_t kind, const char *text) {
    o->secret.ptr = 0;
    o->secret.len = 0;
    o->error_kind = kind;
    return say(&o->head, sizeof *o, BB_MECH_Outcome_Failed, text);
}

static bb_mech_RawOutcome op_resolve_held(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_secret_ResolveIn *i = in;
    bb_secret_ResolveOut *o = out;
    uint8_t name[MATERIAL_CAP];
    size_t name_len = 0, k;
    struct cursor c, probe;
    struct lease *slot = 0;
    if (i->head.size < sizeof *i || o->head.size < sizeof *o) {
        return say(&o->head, sizeof *o, BB_MECH_Outcome_Refused, "resolve: short frame");
    }
    /* The name asked for: {"name": "<string>"}. */
    if (!one_object(i->settings.ptr, i->settings.len)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "resolve: the settings must be a JSON object");
    }
    c.p = i->settings.ptr;
    c.end = i->settings.ptr + i->settings.len;
    ws(&c);
    c.p++;
    if (!member(&c, "name", 0, 0)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID, "resolve: `name` must be a string");
    }
    if (!only_member(i->settings.ptr, i->settings.len, "name")) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "resolve: a reference names only `name`");
    }
    probe = c;
    if (!string(&c, name, sizeof name, &name_len)) {
        /* A well-formed string too long to be held names nothing this plugin holds. */
        if (string(&probe, 0, 0, &name_len)) {
            return resolve_failed(o, BB_SECRET_ERROR_KIND_NOT_FOUND, "no secret by that name");
        }
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID, "resolve: `name` must be a string");
    }
    if (name_len == 0) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "resolve: `name` must be a non-empty string");
    }
    /* The instance's `values` (validated when it was kept). */
    c.p = s->settings;
    c.end = s->settings + s->settings_len;
    ws(&c);
    c.p++;
    if (!member(&c, "values", 0, 0)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INTERNAL, "resolve: the kept settings lost `values`");
    }
    c.p++;
    if (!member(&c, 0, name, name_len)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_NOT_FOUND, "no secret by that name");
    }
    for (k = 0; k < LEASES; k++) {
        if (s->leases[k].id == 0) {
            slot = &s->leases[k];
            break;
        }
    }
    if (slot == 0) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INTERNAL, "resolve: every lease is outstanding");
    }
    if (!string(&c, slot->material, sizeof slot->material, &slot->len)) {
        zero(slot->material, sizeof slot->material);
        slot->len = 0;
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "resolve: the material is larger than a lease holds");
    }
    if (slot->len == 0) {
        /* Fail closed: an empty value is an error, never an empty success. The slot stays free. */
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "resolve: the material is empty; a secret must be non-empty");
    }
    o->error_kind = BB_SECRET_ERROR_KIND_UNSET;
    o->secret.fmt = BB_MECH_BLOB_OCTETS;
    o->secret.flags = BB_MECH_BLOB_SECRET;
    slot->id = s->next_lease++;
    o->secret.ptr = slot->material;
    o->secret.len = slot->len;
    o->head.lease = slot->id;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

/* `check` (secret kind op 10): this plugin judges no reference at config time, so it answers
 * REFUSED, "not served": every reference passes, and `resolve` judges it (the secret kind's
 * `Ops::check` docs). The answer the SDK's unserved slot gives a Rust door that names none: a NULL
 * or short `out` is a FAULT, a NULL `in` is a FAULT, and nothing is written beyond the outcome. */
static bb_mech_RawOutcome op_check(void *inst, const void *in, void *out) {
    bb_mech_OutHead *o = out;
    (void)inst;
    if (o == 0 || o->size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    if (in == 0) {
        o->outcome = (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    o->outcome = (bb_mech_RawOutcome)BB_MECH_Outcome_Refused;
    return (bb_mech_RawOutcome)BB_MECH_Outcome_Refused;
}

/* ---- the ops that touch the instance, under its lock ---- */

#define HELD(op)                                                                                   \
    static bb_mech_RawOutcome op(void *inst, const void *in, void *out) {                          \
        bb_mech_RawOutcome r;                                                                      \
        lock();                                                                                    \
        r = op##_held(inst, in, out);                                                              \
        unlock();                                                                                  \
        return r;                                                                                  \
    }

HELD(op_open)
HELD(op_refresh)
HELD(op_release)
HELD(op_close)
HELD(op_resolve)

/* ---- the table and the door ---- */

static const bb_secret_Ops OPS = {
    .head = { .size = (uint32_t)sizeof(bb_secret_Ops),
              .slots = BB_SECRET_SLOTS,
              .validate = op_validate,
              .open = op_open,
              .refresh = op_refresh,
              .retire = op_ready,
              .tick = op_tick,
              .drive = op_ready,
              .cancel = op_cancel,
              .release = op_release,
              .close = op_close },
    .resolve = op_resolve,
    .check = op_check,
};

/* Designated initializers (here and in OPS): a member the header adds later (the optional `ready`
 * tail op, a further secret op) is zero, i.e. absent, and -Wmissing-field-initializers stays quiet,
 * so this door compiles against the header at any pin. This plugin serves no `ready`. */
static const bb_mech_Door DOOR = {
    .magic = BB_MECH_DOOR_MAGIC,
    .mechanism_version = BB_MECH_MECHANISM_VERSION,
    .size = (uint32_t)sizeof(bb_mech_Door),
    .kind = (uint32_t)BB_MECH_KindCode_Secret,
    .kind_abi = BUSBAR_PLUGIN_KIND_ABI,
    .statement = &STATEMENT,
    .ops = (const bb_mech_OpsHead *)&OPS,
};

/* THE ONE SYMBOL (BB_MECH_DOOR_SYMBOL). */
DOOR_EXPORT const bb_mech_Door *busbar_plugin_door(void) {
    return &DOOR;
}
