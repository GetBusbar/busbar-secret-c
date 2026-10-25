/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors
 *
 * busbar-secret-c's UNIT TESTS: the door driven directly, op by op, for what busbar's conformance
 * script does not judge (it judges the first `bad_settings` entry only, and one malformed
 * reference). This file is NOT part of the plugin: plugin-ci compiles the .c files in secret-c/ only, and this
 * directory is beside them. It uses libc and pthreads; the plugin uses neither.
 *
 * Run (from the repo root, with busbar_plugin.h from busbar at .busbar-ref):
 *
 *   cc -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=thread -g \
 *     -I <busbar>/crates/busbar-contract/include \
 *     -o /tmp/secret-c-unit secret-c/busbar_secret_c.c secret-c/tests/unit.c -lpthread
 *   /tmp/secret-c-unit
 *
 * It exits 0 when every case passes. Under -fsanitize=thread, a data race between `refresh` and
 * `resolve` (the race the instance lock closes) is reported and fails the run.
 */
#define _POSIX_C_SOURCE 200809L
#include "busbar_plugin.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

const bb_mech_Door *busbar_plugin_door(void);

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

/* resolve: the outcome, its error kind and text; a READY lease is released. */
static int resolve(void *inst, const char *settings, uint32_t *kind, char *why, size_t cap) {
    bb_secret_ResolveIn in;
    bb_secret_ResolveOut out;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.head.size = sizeof in;
    in.settings = blob(settings);
    out.head.size = sizeof out;
    secret_ops()->resolve(inst, &in, &out);
    *kind = out.error_kind;
    why[0] = 0;
    if (out.head.outcome == BB_MECH_Outcome_Ready) {
        release(inst, out.head.lease);
    } else if (out.head.error.ptr != 0) {
        snprintf(why, cap, "%.*s", (int)out.head.error.len, (const char *)out.head.error.ptr);
    }
    return out.head.outcome;
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
              strcmp(why, "settings: a `values` entry is empty; a secret must be non-empty") == 0,
          "an empty value is refused at validate: '%s'", why);
    /* 1025 bytes: one past what a lease holds. */
    strcpy(big_value, "{\"values\": {\"big\": \"");
    for (k = 0; k < 1025; k++) {
        strcat(big_value, "x");
    }
    strcat(big_value, "\"}}");
    CHECK(!validate(big_value, why, sizeof why) &&
              strcmp(why, "settings: a `values` entry is larger than a lease holds (1024 bytes)") == 0,
          "a value larger than a lease is refused at validate: '%s'", why);
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
    void *inst = open_instance("{\"values\": {\"db\": \"s3cr3t\", \"\": \"x\"}}");
    CHECK(inst != 0, "opens");
    if (inst == 0) {
        return;
    }
    CHECK(resolve(inst, "{\"name\": \"db\"}", &kind, why, sizeof why) == BB_MECH_Outcome_Ready,
          "a known name resolves");
    CHECK(resolve(inst, "{\"name\": \"\"}", &kind, why, sizeof why) == BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "resolve: `name` must be a non-empty string") == 0,
          "an empty name is INVALID: kind=%u '%s'", kind, why);
    CHECK(resolve(inst, "{\"name\": \"db\", \"path\": \"/x\"}", &kind, why, sizeof why) ==
                  BB_MECH_Outcome_Failed &&
              kind == BB_SECRET_ERROR_KIND_INVALID &&
              strcmp(why, "resolve: a reference names only `name`") == 0,
          "a reference naming another setting is INVALID: kind=%u '%s'", kind, why);
    close_instance(inst);
}

/* refresh and resolve on the one instance from two threads: under -fsanitize=thread the old
 * unlocked instance reports a data race here; every resolve of a held name must be READY. */
static void *refresher(void *inst) {
    int k;
    for (k = 0; k < 2000; k++) {
        refresh(inst, (k & 1) ? "{\"values\": {\"db\": \"one\"}}" : "{\"values\": {\"db\": \"two\"}}");
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
    close_instance(inst);
}

int main(void) {
    settings_are_judged_whole();
    references_name_only_a_non_empty_name();
    refresh_and_resolve_do_not_race();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("secret-c unit: ok\n");
    return 0;
}
