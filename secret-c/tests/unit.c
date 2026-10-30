/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors
 *
 * busbar-secret-c's UNIT TESTS: the door driven directly, op by op, for what busbar's conformance
 * driver does not judge (it judges one malformed reference, and refreshes with good settings
 * before it resolves after a refused refresh). This file is NOT part of the plugin: plugin-ci compiles the .c files in secret-c/ only, and this
 * directory is beside them. It uses libc and pthreads; the plugin uses neither.
 *
 * Run (from the repo root, with busbar_plugin.h from busbar at .busbar-ref):
 *
 *   cc -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=thread -g -DBUSBAR_SECRET_C_UNIT \
 *     -I <busbar>/crates/busbar-contract/include \
 *     -o /tmp/secret-c-unit secret-c/busbar_secret_c.c secret-c/tests/unit.c -lpthread
 *   /tmp/secret-c-unit
 *
 * It exits 0 when every case passes. Under -fsanitize=thread, a data race between `refresh` and
 * `resolve` (the race the instance lock closes) is reported and fails the run. BUSBAR_SECRET_C_UNIT
 * exposes the one instance's memory to this file, so a case can prove what it holds.
 */
#define _POSIX_C_SOURCE 200809L
#include "busbar_plugin.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

const bb_mech_Door *busbar_plugin_door(void);
const void *busbar_secret_c_instance(size_t *len);

static int failures;

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                                   \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fprintf(stderr, "\n");                                                                 \
        }                                                                                          \
    } while (0)

static const bb_mech_OpsHead *head_ops(void) { return busbar_plugin_door()->ops; }
static const bb_secret_Ops *secret_ops(void) {
    return (const bb_secret_Ops *)busbar_plugin_door()->ops;
}

static bb_mech_Blob blob(const char *text) {
    bb_mech_Blob b;
    memset(&b, 0, sizeof b);
    b.ptr = (const uint8_t *)text;
    b.len = strlen(text);
    b.fmt = BB_MECH_BLOB_JSON;
    return b;
}

/* validate: READY (1) or the refusal text in `why`. */
static int validate(const char *settings, char *why, size_t cap) {
    bb_mech_ValidateIn in;
    bb_mech_OutHead out;
    uint8_t buf[256];
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.settings = blob(settings);
    in.err_buf = buf;
    in.err_cap = sizeof buf;
    out.size = sizeof out;
    head_ops()->validate(0, &in, &out);
    why[0] = 0;
    if (out.outcome == BB_MECH_Outcome_Ready) {
        return 1;
    }
    snprintf(why, cap, "%.*s", (int)out.error.len, (const char *)out.error.ptr);
    return 0;
}

static void *open_instance(const char *settings) {
    bb_mech_OpenIn in;
    bb_mech_OpenOut out;
    uint8_t buf[256];
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.settings = blob(settings);
    in.err_buf = buf;
    in.err_cap = sizeof buf;
    out.head.size = sizeof out;
    head_ops()->open(0, &in, &out);
    return out.head.outcome == BB_MECH_Outcome_Ready ? out.instance : 0;
}

static int refresh(void *inst, const char *settings) {
    bb_mech_RefreshIn in;
    bb_mech_OutHead out;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.settings = blob(settings);
    out.size = sizeof out;
    head_ops()->refresh(inst, &in, &out);
    return out.outcome == BB_MECH_Outcome_Ready;
}

static void release(void *inst, uint64_t lease) {
    bb_mech_ReleaseIn in;
    bb_mech_OutHead out;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.lease = lease;
    out.size = sizeof out;
    head_ops()->release(inst, &in, &out);
}

static void close_instance(void *inst) {
    bb_mech_OutHead out;
    memset(&out, 0, sizeof out);
    out.size = sizeof out;
    head_ops()->close(inst, 0, &out);
}


/* open: the refusal text in `why` ("" when it opened; the instance is closed again). */
static int open_text(const char *settings, char *why, size_t cap) {
    bb_mech_OpenIn in;
    bb_mech_OpenOut out;
    uint8_t buf[256];
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.settings = blob(settings);
    in.err_buf = buf;
    in.err_cap = sizeof buf;
    out.head.size = sizeof out;
    head_ops()->open(0, &in, &out);
    why[0] = 0;
    if (out.head.outcome == BB_MECH_Outcome_Ready) {
        close_instance(out.instance);
        return 1;
    }
    snprintf(why, cap, "%.*s", (int)out.err_len, (const char *)buf);
    return 0;
}

/* refresh: the refusal text in `why`. */
static int refresh_text(void *inst, const char *settings, char *why, size_t cap) {
    bb_mech_RefreshIn in;
    bb_mech_OutHead out;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.settings = blob(settings);
    out.size = sizeof out;
    head_ops()->refresh(inst, &in, &out);
    why[0] = 0;
    if (out.outcome == BB_MECH_Outcome_Ready) {
        return 1;
    }
    snprintf(why, cap, "%.*s", (int)out.error.len, (const char *)out.error.ptr);
    return 0;
}

/* resolve into the host's buffer `buf` (`buf_cap` bytes): the `out`, its error text in `why`. */
static bb_secret_ResolveOut resolve_into(void *inst, const char *settings, uint8_t *buf,
                                         size_t buf_cap, char *why, size_t cap) {
    bb_secret_ResolveIn in;
    bb_secret_ResolveOut out;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.settings = blob(settings);
    in.secret_buf = buf;
    in.secret_cap = buf_cap;
    out.head.size = sizeof out;
    secret_ops()->resolve(inst, &in, &out);
    why[0] = 0;
    if (out.head.outcome != BB_MECH_Outcome_Ready && out.head.error.ptr != 0) {
        snprintf(why, cap, "%.*s", (int)out.head.error.len, (const char *)out.head.error.ptr);
    }
    if (out.head.outcome == BB_MECH_Outcome_Ready && out.head.lease != 0) {
        /* A plugin that still leases: hand it back, as a host would. */
        release(inst, out.head.lease);
    }
    return out;
}

/* resolve: the outcome, its error kind and text (the host's buffer wiped after). */
static int resolve(void *inst, const char *settings, uint32_t *kind, char *why, size_t cap) {
    uint8_t buf[BB_SECRET_FIRST_SECRET_CAP];
    bb_secret_ResolveOut out = resolve_into(inst, settings, buf, sizeof buf, why, cap);
    memset(buf, 0, sizeof buf);
    *kind = out.error_kind;
    return out.head.outcome;
}

/* How many times `needle` occurs in the plugin's one instance's memory. */
static int held_copies(const char *needle) {
    size_t len, n = strlen(needle), k;
    const uint8_t *mem = busbar_secret_c_instance(&len);
    int copies = 0;
    for (k = 0; k + n <= len; k++) {
        if (memcmp(mem + k, needle, n) == 0) {
            copies++;
        }
    }
    return copies;
}

#define CANARY "ZEROIZE-CANARY-c-7f3e"

/* THE CREDENTIAL CHIP, ROW 6 (host-owned secret bytes): a READY resolve writes the value into the
 * HOST'S buffer under no lease, and the plugin keeps no copy of it: its one instance holds the value
 * only where its settings name it, and nothing once it is closed. RED while resolve copied the value
 * into a lease of its own. */
static void a_resolve_leaves_no_copy_behind(void) {
    char why[256];
    uint8_t buf[64];
    bb_secret_ResolveOut out;
    void *inst = open_instance("{\"values\": {\"db\": \"" CANARY "\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    CHECK(held_copies(CANARY) == 1, "the settings hold the value once: %d", held_copies(CANARY));
    memset(buf, 0, sizeof buf);
    out = resolve_into(inst, "{\"name\": \"db\"}", buf, sizeof buf, why, sizeof why);
    CHECK(out.head.outcome == BB_MECH_Outcome_Ready, "a known name resolves: %s", why);
    CHECK(out.head.lease == 0, "no lease: the value is the host's (lease %llu)",
          (unsigned long long)out.head.lease);
    CHECK(out.secret.ptr == buf && out.secret.len == strlen(CANARY) &&
              memcmp(buf, CANARY, strlen(CANARY)) == 0,
          "the value is written at the start of the host's buffer");
    CHECK(out.secret.flags == BB_MECH_BLOB_SECRET, "flagged secret");
    CHECK(held_copies(CANARY) == 1, "resolve left a copy in the plugin: %d copies",
          held_copies(CANARY));
    memset(buf, 0, sizeof buf);
    close_instance(inst);
    CHECK(held_copies(CANARY) == 0, "close wiped the settings: %d copies", held_copies(CANARY));
}

/* A value over the host's buffer is the short-buffer answer: FAILED, `needed` its full length,
 * nothing written, no error kind; a buffer that size then resolves it. */
static void a_value_over_the_buffer_is_the_short_answer(void) {
    char why[256];
    uint8_t buf[64];
    size_t n = strlen(CANARY);
    bb_secret_ResolveOut out;
    void *inst = open_instance("{\"values\": {\"db\": \"" CANARY "\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    memset(buf, 0, sizeof buf);
    out = resolve_into(inst, "{\"name\": \"db\"}", buf, n - 1, why, sizeof why);
    CHECK(out.head.outcome == BB_MECH_Outcome_Failed && out.needed == n &&
              out.error_kind == BB_SECRET_ERROR_KIND_UNSET && out.secret.ptr == 0,
          "short: outcome %u needed %llu kind %u", out.head.outcome,
          (unsigned long long)out.needed, out.error_kind);
    CHECK(buf[0] == 0, "a short answer writes nothing");
    out = resolve_into(inst, "{\"name\": \"db\"}", buf, n, why, sizeof why);
    CHECK(out.head.outcome == BB_MECH_Outcome_Ready && out.secret.len == n,
          "the re-call with the size it named resolves");
    memset(buf, 0, sizeof buf);
    close_instance(inst);
}

static char big_value[2200];

static void settings_are_judged_whole(void) {
    char why[256];
    size_t k;
    CHECK(validate("{\"values\": {\"db\": \"x\"}}", why, sizeof why), "good settings: %s", why);
    CHECK(!validate("{\"values\": {\"db\": \"x\"}, \"valuse\": {}}", why, sizeof why) &&
              strcmp(why, "settings: `values` is the only setting") == 0,
          "a setting other than `values` is refused naming why: '%s'", why);
    CHECK(!validate("{\"values\": {\"db\": \"\"}}", why, sizeof why) &&
              strcmp(why, "settings: a `values` entry is EMPTY; a secret must be non-empty (fail-closed)") == 0,
          "an empty value is refused at validate: '%s'", why);
    /* 1025 bytes: one past the most a value may hold (MATERIAL_CAP). */
    strcpy(big_value, "{\"values\": {\"big\": \"");
    for (k = 0; k < 1025; k++) {
        strcat(big_value, "x");
    }
    strcat(big_value, "\"}}");
    CHECK(!validate(big_value, why, sizeof why) &&
              strcmp(why, "settings: a `values` entry is larger than 1024 bytes, the most this "
                          "plugin serves") == 0,
          "a value over the cap is refused at validate: '%s'", why);
    {
        void *opened = open_instance(big_value);
        CHECK(opened == 0, "open refuses what validate refuses");
        if (opened != 0) {
            close_instance(opened);
        }
    }
}

static void references_name_only_a_non_empty_name(void) {
    char why[256];
    uint32_t kind;
    void *inst = open_instance("{\"values\": {\"db\": \"s3cr3t\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    CHECK(resolve(inst, "{\"name\": \"db\"}", &kind, why, sizeof why) == BB_MECH_Outcome_Ready,
          "a known name resolves");
    CHECK(resolve(inst, "{\"name\": \"\"}", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "`name` in secret reference settings must not be blank") == 0,
          "an empty name is INVALID: kind=%u '%s'", kind, why);
    CHECK(resolve(inst, "{\"name\": \"db\", \"path\": \"/x\"}", &kind, why, sizeof why) ==
                  BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "c secret reference names only settings.name (fail-closed)") == 0,
          "a reference naming another setting is INVALID: kind=%u '%s'", kind, why);
    close_instance(inst);
}

/* refresh and resolve on the one instance from two threads: under -fsanitize=thread the old
 * unlocked instance reports a data race here; every resolve of a held name must be READY. */
static int refused_refreshes;

static void *refresher(void *inst) {
    int k;
    for (k = 0; k < 2000; k++) {
        if (!refresh(inst, (k & 1) ? "{\"values\": {\"db\": \"one\"}}"
                                   : "{\"values\": {\"db\": \"two\"}}")) {
            refused_refreshes++;
        }
    }
    return 0;
}

static void refresh_and_resolve_do_not_race(void) {
    pthread_t t;
    char why[256];
    uint32_t kind;
    int k, torn = 0;
    void *inst = open_instance("{\"values\": {\"db\": \"one\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    pthread_create(&t, 0, refresher, inst);
    for (k = 0; k < 2000; k++) {
        if (resolve(inst, "{\"name\": \"db\"}", &kind, why, sizeof why) != BB_MECH_Outcome_Ready) {
            torn++;
        }
    }
    pthread_join(t, 0);
    CHECK(torn == 0, "%d resolves of a held name failed while refresh ran", torn);
    CHECK(refused_refreshes == 0, "%d refreshes were refused: the race was never run",
          refused_refreshes);
    close_instance(inst);
}

/* A value of exactly MATERIAL_CAP bytes is served whole. */
static char cap_value[1100];

static void a_value_at_the_cap_is_served(void) {
    char why[256];
    static uint8_t buf[1024];
    size_t k;
    bb_secret_ResolveOut out;
    void *inst;
    strcpy(cap_value, "{\"values\": {\"cap\": \"");
    for (k = 0; k < 1024; k++) {
        strcat(cap_value, "y");
    }
    strcat(cap_value, "\"}}");
    CHECK(validate(cap_value, why, sizeof why), "a 1024-byte value validates: '%s'", why);
    inst = open_instance(cap_value);
    CHECK(inst != 0, "a 1024-byte value opens");
    if (inst == 0) {
        return;
    }
    out = resolve_into(inst, "{\"name\": \"cap\"}", buf, sizeof buf, why, sizeof why);
    CHECK(out.head.outcome == BB_MECH_Outcome_Ready && out.secret.len == 1024 && buf[0] == 'y' &&
              buf[1023] == 'y',
          "a 1024-byte value resolves whole: outcome %u len %llu '%s'", out.head.outcome,
          (unsigned long long)out.secret.len, why);
    memset(buf, 0, sizeof buf);
    close_instance(inst);
}

/* Every name in `values` can be asked for: an empty one, one longer than a name may be, a name
 * given twice and `values` given twice are refused at validate, open and refresh alike, never kept
 * where no reference can reach them. */
static char long_name[1100];

static void every_kept_name_can_be_resolved(void) {
    char why[256];
    size_t k;
    void *inst;
    CHECK(!validate("{\"values\": {\"a\": \"x\"}, \"values\": {\"b\": \"y\"}}", why, sizeof why) &&
              strcmp(why, "settings: `values` is given more than once") == 0,
          "`values` twice is refused: '%s'", why);
    CHECK(!validate("{\"values\": {\"\": \"x\"}}", why, sizeof why) &&
              strcmp(why, "settings: a `values` name is empty") == 0,
          "an empty name is refused: '%s'", why);
    CHECK(!validate("{\"values\": {\"a\": \"x\", \"b\": \"y\", \"a\": \"z\"}}", why, sizeof why) &&
              strcmp(why, "settings: a `values` name is given more than once") == 0,
          "a name twice is refused: '%s'", why);
    CHECK(!validate("{\"values\": {\"a\": \"x\", \"\\u0061\": \"z\"}}", why, sizeof why) &&
              strcmp(why, "settings: a `values` name is given more than once") == 0,
          "a name twice, once escaped, is refused: '%s'", why);
    CHECK(validate("{\"values\": {\"a\": \"x\", \"ab\": \"y\", \"b\": \"z\"}}", why, sizeof why),
          "distinct names validate: '%s'", why);
    strcpy(long_name, "{\"values\": {\"");
    for (k = 0; k < 1025; k++) {
        strcat(long_name, "n");
    }
    strcat(long_name, "\": \"x\"}}");
    CHECK(!validate(long_name, why, sizeof why) &&
              strcmp(why, "settings: a `values` name is longer than 1024 bytes, the most a "
                          "reference may name") == 0,
          "a name over the cap is refused: '%s'", why);
    inst = open_instance("{\"values\": {\"db\": \"one\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    CHECK(!refresh(inst, "{\"values\": {\"db\": \"one\", \"db\": \"two\"}}"),
          "refresh refuses a name given twice");
    close_instance(inst);
    inst = open_instance("{\"values\": {\"\": \"x\"}}");
    CHECK(inst == 0, "open refuses an empty name");
    if (inst != 0) {
        close_instance(inst);
    }
}

/* A refused refresh keeps the instance serving what it served. */
static void a_refused_refresh_keeps_the_old_values(void) {
    char why[256];
    uint8_t buf[64];
    bb_secret_ResolveOut out;
    void *inst = open_instance("{\"values\": {\"db\": \"one\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    CHECK(!refresh(inst, "{\"values\": {\"db\": \"\"}}"), "an empty value is refused at refresh");
    memset(buf, 0, sizeof buf);
    out = resolve_into(inst, "{\"name\": \"db\"}", buf, sizeof buf, why, sizeof why);
    CHECK(out.head.outcome == BB_MECH_Outcome_Ready && out.secret.len == 3 &&
              memcmp(buf, "one", 3) == 0,
          "the refused refresh kept the old value: '%s'", why);
    memset(buf, 0, sizeof buf);
    close_instance(inst);
}

/* A reference names `name` once, as a string. */
static void a_reference_names_name_once_as_a_string(void) {
    char why[256];
    uint32_t kind;
    void *inst = open_instance("{\"values\": {\"db\": \"one\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    CHECK(resolve(inst, "{\"name\": 5}", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "missing or non-string `name` in secret reference settings") == 0,
          "a number for a name is INVALID: kind=%u '%s'", kind, why);
    CHECK(resolve(inst, "{\"name\": \"db\", \"name\": \"db\"}", &kind, why, sizeof why) ==
                  BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "c secret reference names settings.name once (fail-closed)") == 0,
          "`name` twice is INVALID: kind=%u '%s'", kind, why);
    close_instance(inst);
}

/* RFC 8259 section 7: a character outside the Basic Multilingual Plane is escaped as a surrogate
 * pair; it decodes to its 4-byte UTF-8. An unpaired surrogate is refused, saying so. */
static void a_surrogate_pair_decodes_to_utf8(void) {
    char why[256];
    uint8_t buf[64];
    bb_secret_ResolveOut out;
    void *inst = open_instance("{\"values\": {\"e\": \"a\\ud83d\\ude00b\"}}");
    CHECK(inst != 0, "a surrogate pair opens");
    if (inst != 0) {
        memset(buf, 0, sizeof buf);
        out = resolve_into(inst, "{\"name\": \"e\"}", buf, sizeof buf, why, sizeof why);
        CHECK(out.head.outcome == BB_MECH_Outcome_Ready && out.secret.len == 6 &&
                  memcmp(buf, "a\xF0\x9F\x98\x80" "b", 6) == 0,
              "the pair decodes to U+1F600's UTF-8: outcome %u len %llu '%s'", out.head.outcome,
              (unsigned long long)out.secret.len, why);
        memset(buf, 0, sizeof buf);
        close_instance(inst);
    }
    CHECK(!validate("{\"values\": {\"e\": \"\\ud83d\"}}", why, sizeof why) &&
              strcmp(why, "settings: must be a JSON object; nested at most 32 deep, with no "
                          "unpaired \\u surrogate") == 0,
          "an unpaired high surrogate is refused naming why: '%s'", why);
    CHECK(!validate("{\"values\": {\"e\": \"\\ude00\"}}", why, sizeof why),
          "an unpaired low surrogate is refused");
    CHECK(!validate("{\"values\": {\"e\": \"\\ud83d\\u0041\"}}", why, sizeof why),
          "a high surrogate followed by a non-surrogate is refused");
}

/* An `out` shorter than its head is a FAULT, written nothing, at every op (as `check` answers). */
static void a_short_out_is_a_fault(void) {
    bb_mech_ValidateIn vin;
    bb_mech_RefreshIn rin;
    bb_mech_ReleaseIn lin;
    bb_mech_OutHead out;
    uint8_t buf[64];
    void *inst = open_instance("{\"values\": {\"db\": \"one\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    memset(&vin, 0, sizeof vin);
    vin.head.size = sizeof vin;
    vin.settings = blob("[]");
    vin.err_buf = buf;
    vin.err_cap = sizeof buf;
    memset(&out, 0, sizeof out);
    out.size = 4;
    CHECK(head_ops()->validate(0, &vin, &out) == BB_MECH_Outcome_Fault && out.error.len == 0 &&
              out.outcome == 0,
          "validate: a short out is a FAULT");
    memset(&rin, 0, sizeof rin);
    rin.head.size = sizeof rin;
    rin.settings = blob("[]");
    memset(&out, 0, sizeof out);
    out.size = 4;
    CHECK(head_ops()->refresh(inst, &rin, &out) == BB_MECH_Outcome_Fault && out.error.len == 0,
          "refresh: a short out is a FAULT");
    memset(&lin, 0, sizeof lin);
    lin.head.size = sizeof lin;
    lin.lease = 1;
    memset(&out, 0, sizeof out);
    out.size = 4;
    CHECK(head_ops()->release(inst, &lin, &out) == BB_MECH_Outcome_Fault && out.error.len == 0,
          "release: a short out is a FAULT");
    memset(&out, 0, sizeof out);
    out.size = 4;
    CHECK(head_ops()->retire(inst, 0, &out) == BB_MECH_Outcome_Fault && out.outcome == 0,
          "retire: a short out is a FAULT");
    memset(&out, 0, sizeof out);
    out.size = 4;
    CHECK(head_ops()->close(inst, 0, &out) == BB_MECH_Outcome_Fault && out.outcome == 0,
          "close: a short out is a FAULT");
    CHECK(held_copies("one") == 1, "a faulted close left the instance as it was");
    close_instance(inst);
}


#define NOT_OBJECT_TEXT                                                                            \
    "settings: must be a JSON object; nested at most 32 deep, with no unpaired \\u surrogate"
#define NONE_TEXT "settings: c requires settings (values); none provided"

/* C4: instance settings of no bytes are refused saying a plugin requires them; a non-object says
 * so in the shared grammar. validate, open and refresh alike. */
static void instance_settings_use_the_shared_grammar(void) {
    char why[256];
    void *inst;
    CHECK(!validate("", why, sizeof why) && strcmp(why, NONE_TEXT) == 0,
          "validate: empty settings: '%s'", why);
    CHECK(!open_text("", why, sizeof why) && strcmp(why, NONE_TEXT) == 0,
          "open: empty settings: '%s'", why);
    CHECK(!validate("[]", why, sizeof why) && strcmp(why, NOT_OBJECT_TEXT) == 0,
          "validate: a non-object: '%s'", why);
    CHECK(!open_text("[]", why, sizeof why) && strcmp(why, NOT_OBJECT_TEXT) == 0,
          "open: a non-object: '%s'", why);
    inst = open_instance("{\"values\": {\"db\": \"one\"}}");
    CHECK(inst != 0, "opens");
    if (inst != 0) {
        CHECK(!refresh_text(inst, "", why, sizeof why) && strcmp(why, NONE_TEXT) == 0,
              "refresh: empty settings: '%s'", why);
        CHECK(!refresh_text(inst, "[]", why, sizeof why) && strcmp(why, NOT_OBJECT_TEXT) == 0,
              "refresh: a non-object: '%s'", why);
        close_instance(inst);
    }
}

/* C1/C5: the reference refusals in the vault grammar (the kernel adds the module prefix), and an
 * empty reference blob is `{}` (the SDK's settings_of). */
static void reference_refusals_use_the_vault_grammar(void) {
    char why[256];
    uint32_t kind;
    void *inst = open_instance("{\"values\": {\"db\": \"s3cr3t\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    CHECK(resolve(inst, "[]", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "secret settings are not a JSON object") == 0,
          "a non-object reference: kind=%u '%s'", kind, why);
    CHECK(resolve(inst, "", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "missing or non-string `name` in secret reference settings") == 0,
          "an empty reference is {} (missing name): kind=%u '%s'", kind, why);
    CHECK(resolve(inst, "{}", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "missing or non-string `name` in secret reference settings") == 0,
          "{} is missing name: kind=%u '%s'", kind, why);
    CHECK(resolve(inst, "{\"name\": \"nope\"}", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_NOT_FOUND &&
              strcmp(why, "c holds no secret by that name") == 0,
          "an unknown name: kind=%u '%s'", kind, why);
    close_instance(inst);
}

/* C2: the empty-material text carries the shared tail. validate refuses an empty value, so a kept
 * `values` entry is made empty in place (same length, trailing blank) to reach resolve's guard. */
static void resolve_refuses_empty_material_in_the_shared_words(void) {
    char why[256];
    uint32_t kind;
    size_t len, k;
    const char *from = "{\"values\": {\"db\": \" \"}}";
    const char *to = "{\"values\": {\"db\": \"\"}} ";
    uint8_t *mem;
    void *inst = open_instance(from);
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    mem = (uint8_t *)busbar_secret_c_instance(&len);
    for (k = 0; k + strlen(from) <= len; k++) {
        if (memcmp(mem + k, from, strlen(from)) == 0) {
            memcpy(mem + k, to, strlen(to));
            break;
        }
    }
    CHECK(k + strlen(from) <= len, "found the kept settings");
    CHECK(resolve(inst, "{\"name\": \"db\"}", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "the material is EMPTY; a secret must be non-empty (fail-closed)") == 0,
          "an empty material: kind=%u '%s'", kind, why);
    close_instance(inst);
}

/* C3: release is refused, SDK words first. */
static void release_is_refused_in_the_sdk_words(void) {
    bb_mech_ReleaseIn in;
    bb_mech_OutHead out;
    char why[256];
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.lease = 1;
    out.size = sizeof out;
    CHECK(head_ops()->release(0, &in, &out) == BB_MECH_Outcome_Refused, "release is refused");
    snprintf(why, sizeof why, "%.*s", (int)out.error.len, (const char *)out.error.ptr);
    CHECK(strcmp(why, "release: no such lease (a resolved value is written into the host's "
                      "buffer, never leased)") == 0,
          "release text: '%s'", why);
}

/* C7: the Statement states its config word: one REWRITE_ALIAS from `secret-c`. */
static void the_statement_states_its_alias(void) {
    const bb_mech_Statement *st = busbar_plugin_door()->statement;
    CHECK(st->rewrites != 0 && st->rewrites_len == 1, "one rewrite: len %llu",
          (unsigned long long)st->rewrites_len);
    if (st->rewrites != 0 && st->rewrites_len == 1) {
        CHECK(st->rewrites[0].class_ == BB_MECH_REWRITE_ALIAS, "an alias rewrite");
        CHECK(st->rewrites[0].from.len == 8 && memcmp(st->rewrites[0].from.ptr, "secret-c", 8) == 0,
              "from is `secret-c`");
        CHECK(st->rewrites[0].to.len == 0, "to is empty");
    }
}

/* C6: an `out` shorter than its head (or NULL) is a FAULT at open, resolve, tick and cancel too. */
static void a_short_out_is_a_fault_at_the_rest(void) {
    bb_mech_OpenIn oin;
    bb_mech_OpenOut oout;
    bb_secret_ResolveIn rin;
    bb_secret_ResolveOut rout;
    bb_mech_TickOut tout;
    bb_mech_CancelOut cout_;
    uint8_t buf[64];
    void *inst = open_instance("{\"values\": {\"db\": \"one\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    memset(&oin, 0, sizeof oin);
    oin.head.size = sizeof oin;
    oin.settings = blob("{\"values\": {\"db\": \"two\"}}");
    oin.err_buf = buf;
    oin.err_cap = sizeof buf;
    memset(&oout, 0, sizeof oout);
    oout.head.size = 4;
    CHECK(head_ops()->open(0, &oin, &oout) == BB_MECH_Outcome_Fault && oout.err_len == 0,
          "open: a short out is a FAULT");
    CHECK(head_ops()->open(0, &oin, 0) == BB_MECH_Outcome_Fault, "open: a NULL out is a FAULT");
    memset(buf, 0, sizeof buf);
    memset(&rin, 0, sizeof rin);
    rin.head.size = sizeof rin;
    rin.settings = blob("{\"name\": \"db\"}");
    rin.secret_buf = buf;
    rin.secret_cap = sizeof buf;
    memset(&rout, 0, sizeof rout);
    rout.head.size = 4;
    CHECK(secret_ops()->resolve(inst, &rin, &rout) == BB_MECH_Outcome_Fault &&
              rout.secret.len == 0 && buf[0] == 0,
          "resolve: a short out is a FAULT, nothing written");
    CHECK(secret_ops()->resolve(inst, &rin, 0) == BB_MECH_Outcome_Fault,
          "resolve: a NULL out is a FAULT");
    memset(&tout, 0, sizeof tout);
    tout.head.size = 4;
    CHECK(head_ops()->tick(inst, 0, &tout) == BB_MECH_Outcome_Fault && tout.head.outcome == 0,
          "tick: a short out is a FAULT");
    CHECK(head_ops()->tick(inst, 0, 0) == BB_MECH_Outcome_Fault, "tick: a NULL out is a FAULT");
    memset(&cout_, 0, sizeof cout_);
    cout_.head.size = 4;
    CHECK(head_ops()->cancel(inst, 0, &cout_) == BB_MECH_Outcome_Fault && cout_.head.outcome == 0,
          "cancel: a short out is a FAULT");
    CHECK(head_ops()->cancel(inst, 0, 0) == BB_MECH_Outcome_Fault,
          "cancel: a NULL out is a FAULT");
    close_instance(inst);
}

int main(void) {
    a_resolve_leaves_no_copy_behind();
    a_value_over_the_buffer_is_the_short_answer();
    settings_are_judged_whole();
    references_name_only_a_non_empty_name();
    refresh_and_resolve_do_not_race();
    a_value_at_the_cap_is_served();
    every_kept_name_can_be_resolved();
    a_refused_refresh_keeps_the_old_values();
    a_reference_names_name_once_as_a_string();
    a_surrogate_pair_decodes_to_utf8();
    a_short_out_is_a_fault();
    instance_settings_use_the_shared_grammar();
    reference_refusals_use_the_vault_grammar();
    resolve_refuses_empty_material_in_the_shared_words();
    release_is_refused_in_the_sdk_words();
    the_statement_states_its_alias();
    a_short_out_is_a_fault_at_the_rest();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("secret-c unit: ok\n");
    return 0;
}
