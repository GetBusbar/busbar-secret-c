/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors
















































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
#define TEXT_(x) #x
#define TEXT(x) TEXT_(x)


#define SETTINGS_CAP 8192
#define MATERIAL_CAP 1024

#define DEPTH_CAP 32




static const bb_mech_Rewrite REWRITES[] = {
    { .class_ = BB_MECH_REWRITE_ALIAS, .from = STR("secret-c"), .to = STR("") },
};

static const bb_mech_Statement STATEMENT = {
    .size = (uint32_t)sizeof(bb_mech_Statement),
    .kind = (uint32_t)BB_MECH_KindCode_Secret,
    .kind_abi = BUSBAR_PLUGIN_KIND_ABI,
    .max_inflight = 1,
    .name = STR("busbar-secret-c"),
    .version = STR("1.6.0"),
    .marks = BB_MECH_MARK_ONE_INSTANCE,
    .rewrites = REWRITES,
    .rewrites_len = sizeof REWRITES / sizeof REWRITES[0],
};



struct instance {
    int open;
    size_t settings_len;
    uint8_t settings[SETTINGS_CAP];
};

static struct instance THE_INSTANCE;



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



static bb_mech_RawOutcome answer(bb_mech_OutHead *head, size_t own, bb_mech_Outcome outcome) {
    if (head->size > own) {
        head->size = (uint32_t)own;
    }
    head->outcome = (bb_mech_RawOutcome)outcome;
    return (bb_mech_RawOutcome)outcome;
}


static bb_mech_RawOutcome say(bb_mech_OutHead *head, size_t own, bb_mech_Outcome outcome,
                              const char *text) {
    head->error.ptr = (const uint8_t *)text;
    head->error.len = length(text);
    return answer(head, own, outcome);
}


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




static void input_field(void *to, size_t width, const void *in, size_t size, size_t offset) {
    size_t k;
    uint8_t *dst = to;
    const uint8_t *src = in;
    if (offset > size || width > size - offset) {
        return;
    }
    for (k = 0; k < width; k++) {
        dst[k] = src[offset + k];
    }
}



static bb_mech_Blob input_blob(const void *in, size_t size, size_t offset) {
    bb_mech_Blob b = { 0 };
    input_field(&b.ptr, sizeof b.ptr, in, size, offset + offsetof(bb_mech_Blob, ptr));
    input_field(&b.len, sizeof b.len, in, size, offset + offsetof(bb_mech_Blob, len));
    input_field(&b.fmt, sizeof b.fmt, in, size, offset + offsetof(bb_mech_Blob, fmt));
    input_field(&b.flags, sizeof b.flags, in, size, offset + offsetof(bb_mech_Blob, flags));
    return b;
}



struct cursor {
    const uint8_t *p;
    const uint8_t *end;
};

static void ws(struct cursor *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) {
        c->p++;
    }
}


static int hex_in(volatile int *h) {
    if (*h >= '0' && *h <= '9') { *h -= '0'; return 1; }
    if (*h >= 'a' && *h <= 'f') { *h = *h - 'a' + 10; return 1; }
    if (*h >= 'A' && *h <= 'F') { *h = *h - 'A' + 10; return 1; }
    return 0;
}

struct string_scratch {
    uint8_t b;
    uint32_t cp, lo;
    int h;
    uint8_t enc[4];
};


static int string_in(struct cursor *c, uint8_t *out, size_t cap, size_t *len,
                     volatile struct string_scratch *s) {
    size_t n = 0;
    if (c->p >= c->end || *c->p != '"') {
        return 0;
    }
    c->p++;
    while (c->p < c->end) {
        size_t k, m;
        s->b = *c->p++;
        if (s->b == '"') {
            *len = n;
            return 1;
        }
        if (s->b < 0x20) {
            return 0;
        }
        if (s->b != '\\') {
            s->enc[0] = s->b;
            m = 1;
        } else {
            if (c->p >= c->end) {
                return 0;
            }
            s->b = *c->p++;
            m = 1;
            switch (s->b) {
            case '"': s->enc[0] = '"'; break;
            case '\\': s->enc[0] = '\\'; break;
            case '/': s->enc[0] = '/'; break;
            case 'b': s->enc[0] = '\b'; break;
            case 'f': s->enc[0] = '\f'; break;
            case 'n': s->enc[0] = '\n'; break;
            case 'r': s->enc[0] = '\r'; break;
            case 't': s->enc[0] = '\t'; break;
            case 'u':
                if (c->end - c->p < 4) {
                    return 0;
                }
                s->cp = 0;
                for (k = 0; k < 4; k++) {
                    s->h = c->p[k];
                    if (!hex_in(&s->h)) {
                        return 0;
                    }
                    s->cp = s->cp * 16 + (uint32_t)s->h;
                }
                c->p += 4;
                if (s->cp >= 0xDC00 && s->cp <= 0xDFFF) {
                    return 0;
                }
                if (s->cp >= 0xD800 && s->cp <= 0xDBFF) {


                    s->lo = 0;
                    if (c->end - c->p < 6 || c->p[0] != '\\' || c->p[1] != 'u') {
                        return 0;
                    }
                    for (k = 0; k < 4; k++) {
                        s->h = c->p[2 + k];
                        if (!hex_in(&s->h)) {
                            return 0;
                        }
                        s->lo = s->lo * 16 + (uint32_t)s->h;
                    }
                    if (s->lo < 0xDC00 || s->lo > 0xDFFF) {
                        return 0;
                    }
                    c->p += 6;
                    s->cp = 0x10000 + ((s->cp - 0xD800) << 10) + (s->lo - 0xDC00);
                }
                if (s->cp < 0x80) {
                    s->enc[0] = (uint8_t)s->cp;
                } else if (s->cp < 0x800) {
                    s->enc[0] = (uint8_t)(0xC0 | (s->cp >> 6));
                    s->enc[1] = (uint8_t)(0x80 | (s->cp & 0x3F));
                    m = 2;
                } else if (s->cp < 0x10000) {
                    s->enc[0] = (uint8_t)(0xE0 | (s->cp >> 12));
                    s->enc[1] = (uint8_t)(0x80 | ((s->cp >> 6) & 0x3F));
                    s->enc[2] = (uint8_t)(0x80 | (s->cp & 0x3F));
                    m = 3;
                } else {
                    s->enc[0] = (uint8_t)(0xF0 | (s->cp >> 18));
                    s->enc[1] = (uint8_t)(0x80 | ((s->cp >> 12) & 0x3F));
                    s->enc[2] = (uint8_t)(0x80 | ((s->cp >> 6) & 0x3F));
                    s->enc[3] = (uint8_t)(0x80 | (s->cp & 0x3F));
                    m = 4;
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
                out[n] = s->enc[k];
            }
            n++;
        }
    }
    return 0;
}






static int string(struct cursor *c, uint8_t *out, size_t cap, size_t *len) {
    volatile struct string_scratch scratch = { 0 };
    int r = string_in(c, out, cap, len, &scratch);
    zero((volatile uint8_t *)&scratch, sizeof scratch);
    return r;
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



static int key_is(struct cursor *c, const uint8_t *want, size_t want_len) {
    uint8_t key[MATERIAL_CAP];
    size_t n;
    struct cursor probe = *c;
    if (!string(&probe, key, sizeof key, &n)) {

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
        c->p++;
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

static const char NOT_AN_OBJECT[] = "settings: must be a JSON object; nested at most "
                                    TEXT(DEPTH_CAP) " deep, with no unpaired \\u surrogate";
static const char NO_SETTINGS[] = "settings: c requires settings (values); none provided";
static const char NO_VALUES[] = "settings: `values` must be an object";
static const char REQUIRED_VALUES[] = "settings: `values` is required";
static const char ONLY_VALUES[] = "settings: `values` is the only setting";
static const char VALUES_TWICE[] = "settings: `values` is given more than once";
static const char EMPTY_NAME[] = "settings: a `values` name is empty";
static const char NAME_TOO_LARGE[] = "settings: a `values` name is longer than " TEXT(MATERIAL_CAP)
                                     " bytes, the most a reference may name";
static const char NAME_TWICE[] = "settings: a `values` name is given more than once";
static const char NOT_STRINGS[] = "settings: every `values` entry must be a string";
static const char EMPTY_VALUE[] = "settings: a `values` entry is EMPTY; a secret must be non-empty (fail-closed)";
static const char VALUE_TOO_LARGE[] = "settings: a `values` entry is larger than " TEXT(
    MATERIAL_CAP) " bytes, the most this plugin serves";
static const char NO_LEASE[] =
    "release: no such lease (a resolved value is written into the host's buffer, never leased)";
static const char MISSING_NAME[] = "missing or non-string `name` in secret reference settings";
static const char NO_SUCH_NAME[] = "c holds no secret by that name";
static const char TOO_LARGE[] = "settings: larger than " TEXT(SETTINGS_CAP)
                                " bytes, the most this plugin keeps";
static const char BAD_REFERENCE_OBJECT[] =
    "secret reference settings must be well-formed JSON, nested at most " TEXT(DEPTH_CAP)
    " deep, with no unpaired \\u surrogate";



static int named_before(const uint8_t *from, const uint8_t *upto, const uint8_t *end,
                        const uint8_t *name, size_t len) {
    uint8_t seen[MATERIAL_CAP];
    struct cursor c;
    size_t n, k;
    c.p = from;
    c.end = end;
    for (;;) {
        ws(&c);
        if (c.p >= upto || !string(&c, seen, sizeof seen, &n)) {
            return 0;
        }
        if (n == len) {
            for (k = 0; k < n && seen[k] == name[k]; k++) {
            }
            if (k == n) {
                return 1;
            }
        }
        ws(&c);
        c.p++;
        if (!value(&c, 1)) {
            return 0;
        }
        ws(&c);
        c.p++;
    }
}





static const char *values_refusal(struct cursor *c) {
    const uint8_t *first;
    c->p++;
    ws(c);
    if (c->p < c->end && *c->p == '}') {
        c->p++;
        return 0;
    }
    first = c->p;
    for (;;) {
        uint8_t name[MATERIAL_CAP];
        const uint8_t *at;
        size_t n;
        ws(c);
        at = c->p;
        if (!string(c, name, sizeof name, &n)) {

            return NAME_TOO_LARGE;
        }
        if (n == 0) {
            return EMPTY_NAME;
        }
        if (named_before(first, at, c->end, name, n)) {
            return NAME_TWICE;
        }
        ws(c);
        c->p++;
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
        c->p++;
        return 0;
    }
}



static const char *settings_refusal(const uint8_t *ptr, size_t len) {
    struct cursor c;
    int seen = 0;
    if (len == 0) {
        return NO_SETTINGS;
    }
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
        return REQUIRED_VALUES;
    }
    for (;;) {
        const char *why;
        ws(&c);
        if (key_is(&c, (const uint8_t *)"values", length("values")) != 1) {
            return ONLY_VALUES;
        }
        if (seen) {
            return VALUES_TWICE;
        }
        seen = 1;
        ws(&c);
        c.p++;
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



static int only_member(const uint8_t *ptr, size_t len, const char *want) {
    int count = 0;
    struct cursor c;
    c.p = ptr;
    c.end = ptr + len;
    ws(&c);
    c.p++;
    ws(&c);
    if (c.p < c.end && *c.p == '}') {
        return 0;
    }
    for (;;) {
        ws(&c);
        if (key_is(&c, (const uint8_t *)want, length(want)) != 1) {
            return -1;
        }
        count++;
        ws(&c);
        c.p++;
        if (!value(&c, 1)) {
            return -1;
        }
        ws(&c);
        if (c.p < c.end && *c.p == ',') {
            c.p++;
            continue;
        }
        return count;
    }
}



static bb_mech_RawOutcome op_validate(void *inst, const void *in, void *out) {
    const bb_mech_InHead *head = in;
    bb_mech_OutHead *o = out;
    bb_mech_Blob settings;
    uint8_t *err_buf = 0;
    size_t err_cap = 0;
    const char *why;
    size_t n;
    (void)inst;
    if (o == 0 || o->size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    if (head == 0) {
        return answer(o, sizeof *o, BB_MECH_Outcome_Fault);
    }
    settings = input_blob(in, head->size, offsetof(bb_mech_ValidateIn, settings));
    input_field(&err_buf, sizeof err_buf, in, head->size, offsetof(bb_mech_ValidateIn, err_buf));
    input_field(&err_cap, sizeof err_cap, in, head->size, offsetof(bb_mech_ValidateIn, err_cap));
    why = settings_refusal(settings.ptr, settings.len);
    if (why == 0) {
        return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
    }

    n = lend(err_buf, err_cap, why);
    o->error.ptr = err_buf;
    o->error.len = n;
    return answer(o, sizeof *o, BB_MECH_Outcome_Failed);
}


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

static bb_mech_RawOutcome op_open_held(void *inst, const void *in, void *out) {
    const bb_mech_InHead *head = in;
    bb_mech_OpenOut *o = out;
    bb_mech_Blob settings;
    uint8_t *err_buf = 0;
    size_t err_cap = 0;
    const char *why;
    (void)inst;
    if (o == 0 || o->head.size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    if (head == 0) {
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Fault);
    }
    settings = input_blob(in, head->size, offsetof(bb_mech_OpenIn, settings));
    input_field(&err_buf, sizeof err_buf, in, head->size, offsetof(bb_mech_OpenIn, err_buf));
    input_field(&err_cap, sizeof err_cap, in, head->size, offsetof(bb_mech_OpenIn, err_cap));
    if (THE_INSTANCE.open) {
        o->err_len = lend(err_buf, err_cap, "one instance only");
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    why = keep(&THE_INSTANCE, &settings);
    if (why != 0) {
        o->err_len = lend(err_buf, err_cap, why);
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    THE_INSTANCE.open = 1;
    o->instance = &THE_INSTANCE;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_refresh_held(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_mech_InHead *head = in;
    bb_mech_OutHead *o = out;
    bb_mech_Blob settings;
    const char *why;
    if (o == 0 || o->size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    if (head == 0) {
        return answer(o, sizeof *o, BB_MECH_Outcome_Fault);
    }
    settings = input_blob(in, head->size, offsetof(bb_mech_RefreshIn, settings));
    why = keep(s, &settings);
    if (why != 0) {
        return say(o, sizeof *o, BB_MECH_Outcome_Failed, why);
    }
    return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_ready(void *inst, const void *in, void *out) {
    bb_mech_OutHead *o = out;
    (void)inst;
    (void)in;
    if (o == 0 || o->size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_tick(void *inst, const void *in, void *out) {
    bb_mech_TickOut *o = out;
    (void)inst;
    (void)in;
    if (o == 0 || o->head.size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    o->next_tick_ns = 0;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_cancel(void *inst, const void *in, void *out) {
    bb_mech_CancelOut *o = out;
    (void)inst;
    (void)in;
    if (o == 0 || o->head.size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    o->disposition = BB_SECRET_CANCEL_ABORTED;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}


static bb_mech_RawOutcome op_release(void *inst, const void *in, void *out) {
    bb_mech_OutHead *o = out;
    (void)inst;
    if (o == 0 || o->size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    if (in == 0) {
        return answer(o, sizeof *o, BB_MECH_Outcome_Fault);
    }

    return say(o, sizeof *o, BB_MECH_Outcome_Refused, NO_LEASE);
}

static bb_mech_RawOutcome op_close_held(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    bb_mech_OutHead *o = out;
    (void)in;
    if (o == 0 || o->size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    zero(s->settings, sizeof s->settings);
    s->settings_len = 0;
    s->open = 0;
    return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
}



static bb_mech_RawOutcome resolve_failed(bb_secret_ResolveOut *o, uint32_t kind, const char *text) {
    o->secret.ptr = 0;
    o->secret.len = 0;
    o->error_kind = kind;
    o->needed = 0;
    return say(&o->head, sizeof *o, BB_MECH_Outcome_Failed, text);
}

static bb_mech_RawOutcome op_resolve_held(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_mech_InHead *head = in;
    bb_secret_ResolveOut *o = out;
    bb_mech_Blob settings;
    uint8_t *secret_buf = 0;
    size_t secret_cap = 0;
    uint8_t name[MATERIAL_CAP];
    size_t name_len = 0, len = 0;
    int members;
    struct cursor c, probe;
    if (o == 0 || o->head.size < sizeof *o) {
        return (bb_mech_RawOutcome)BB_MECH_Outcome_Fault;
    }
    if (head == 0) {
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Fault);
    }
    settings = input_blob(in, head->size, offsetof(bb_secret_ResolveIn, settings));
    input_field(&secret_buf, sizeof secret_buf, in, head->size,
                offsetof(bb_secret_ResolveIn, secret_buf));
    input_field(&secret_cap, sizeof secret_cap, in, head->size,
                offsetof(bb_secret_ResolveIn, secret_cap));

    if (settings.len == 0) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID, MISSING_NAME);
    }
    if (!one_object(settings.ptr, settings.len)) {
        if (settings.ptr != 0) {
            c.p = settings.ptr;
            c.end = settings.ptr + settings.len;
            ws(&c);
            if (c.p < c.end && *c.p == '{') {
                return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID, BAD_REFERENCE_OBJECT);
            }
        }
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "secret settings are not a JSON object");
    }
    c.p = settings.ptr;
    c.end = settings.ptr + settings.len;
    ws(&c);
    c.p++;
    if (!member(&c, "name", 0, 0)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID, MISSING_NAME);
    }
    members = only_member(settings.ptr, settings.len, "name");
    if (members < 0) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "c secret reference names only settings.name (fail-closed)");
    }
    if (members != 1) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "c secret reference names settings.name once (fail-closed)");
    }
    probe = c;
    if (!string(&c, name, sizeof name, &name_len)) {

        if (string(&probe, 0, 0, &name_len)) {
            return resolve_failed(o, BB_SECRET_ERROR_KIND_NOT_FOUND, NO_SUCH_NAME);
        }
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID, MISSING_NAME);
    }
    if (name_len == 0) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "`name` in secret reference settings must not be blank");
    }

    c.p = s->settings;
    c.end = s->settings + s->settings_len;
    ws(&c);
    c.p++;
    if (!member(&c, "values", 0, 0)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INTERNAL, "resolve: the kept settings lost `values`");
    }
    c.p++;
    if (!member(&c, 0, name, name_len)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_NOT_FOUND, NO_SUCH_NAME);
    }


    probe = c;
    if (!string(&probe, 0, 0, &len)) {
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INTERNAL,
                              "resolve: the kept settings hold a malformed value");
    }
    if (len == 0) {

        return resolve_failed(o, BB_SECRET_ERROR_KIND_INVALID,
                              "the material is EMPTY; a secret must be non-empty (fail-closed)");
    }
    if (secret_buf == 0 || len > secret_cap) {

        o->secret.ptr = 0;
        o->secret.len = 0;
        o->error_kind = BB_SECRET_ERROR_KIND_UNSET;
        o->needed = len;
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    if (!string(&c, secret_buf, secret_cap, &len)) {
        zero(secret_buf, secret_cap);
        return resolve_failed(o, BB_SECRET_ERROR_KIND_INTERNAL,
                              "resolve: the material did not decode into the host's buffer");
    }
    o->error_kind = BB_SECRET_ERROR_KIND_UNSET;
    o->needed = 0;
    o->secret.fmt = BB_MECH_BLOB_OCTETS;
    o->secret.flags = BB_MECH_BLOB_SECRET;
    o->secret.ptr = secret_buf;
    o->secret.len = len;
    o->head.lease = 0;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}





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
HELD(op_close)
HELD(op_resolve)



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






static const bb_mech_Door DOOR = {
    .magic = BB_MECH_DOOR_MAGIC,
    .mechanism_version = BB_MECH_MECHANISM_VERSION,
    .size = (uint32_t)sizeof(bb_mech_Door),
    .kind = (uint32_t)BB_MECH_KindCode_Secret,
    .kind_abi = BUSBAR_PLUGIN_KIND_ABI,
    .statement = &STATEMENT,
    .ops = (const bb_mech_OpsHead *)&OPS,
    .layout = BB_SECRET_LAYOUT_FINGERPRINT,
};
_Static_assert(offsetof(bb_mech_Door, layout) == 56 && sizeof(bb_mech_Door) == 64,
               "the door states its layout fingerprint at offset 56 of a 64-byte door");

#ifdef BUSBAR_SECRET_C_UNIT


const void *busbar_secret_c_instance(size_t *len);
const void *busbar_secret_c_instance(size_t *len) {
    *len = THE_INSTANCE.settings_len;
    return THE_INSTANCE.settings;
}
#endif


DOOR_EXPORT const bb_mech_Door *busbar_plugin_door(void) {
    return &DOOR;
}
