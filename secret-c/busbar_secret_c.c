/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors
 *
 * busbar-secret-c: a busbar `kind: secret` plugin in C, from busbar_plugin.h ALONE (no Rust, no busbar
 * crate, no libc header). The skeleton `busbar-release plugin new --lang c` renders: every op of the
 * secret table answers within the kind's contract, and `resolve` holds no secret yet (FAILED,
 * NOT_FOUND). Replace it with the plugin, and `conformance.json` with its inputs.
 *
 * BUSBAR_PLUGIN_KIND_ABI (default BB_SECRET_ABI_VERSION) is the kind ABI the door and its Statement
 * state: busbar's C conformance rebuilds this source at another value (its RED arm) and requires
 * the loader to refuse that build.
 */
#include "busbar_plugin.h"

#ifndef BUSBAR_PLUGIN_KIND_ABI
#define BUSBAR_PLUGIN_KIND_ABI BB_SECRET_ABI_VERSION
#endif

#if defined(_WIN32)
#define DOOR_EXPORT __declspec(dllexport)
#else
#define DOOR_EXPORT __attribute__((visibility("default")))
#endif

#define STR(s) { (const uint8_t *)(s), sizeof(s) - 1 }

static const bb_mech_Statement STATEMENT = {
    .size = (uint32_t)sizeof(bb_mech_Statement),
    .kind = (uint32_t)BB_MECH_KindCode_Secret,
    .kind_abi = BUSBAR_PLUGIN_KIND_ABI,
    .max_inflight = 1,
    .name = STR("busbar-secret-c"),
    .version = STR("0.1.0"),
    .marks = BB_MECH_MARK_ONE_INSTANCE,
};

static int THE_INSTANCE;

static bb_mech_RawOutcome answer(bb_mech_OutHead *head, size_t own, bb_mech_Outcome outcome) {
    if (head->size > own) {
        head->size = (uint32_t)own;
    }
    head->outcome = (bb_mech_RawOutcome)outcome;
    return (bb_mech_RawOutcome)outcome;
}

static bb_mech_RawOutcome op_open(void *inst, const void *in, void *out) {
    bb_mech_OpenOut *o = out;
    (void)inst;
    (void)in;
    o->instance = &THE_INSTANCE;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
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

static bb_mech_RawOutcome op_release(void *inst, const void *in, void *out) {
    bb_mech_OutHead *o = out;
    (void)inst;
    (void)in;
    return answer(o, sizeof *o, BB_MECH_Outcome_Refused); /* no lease is ever granted */
}

static bb_mech_RawOutcome op_resolve(void *inst, const void *in, void *out) {
    bb_secret_ResolveOut *o = out;
    static const char why[] = "this plugin holds no secret yet";
    (void)inst;
    (void)in;
    o->error_kind = BB_SECRET_ERROR_KIND_NOT_FOUND;
    o->head.error.ptr = (const uint8_t *)why;
    o->head.error.len = sizeof why - 1;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
}

static const bb_secret_Ops OPS = {
    {
        (uint32_t)sizeof(bb_secret_Ops),
        BB_SECRET_SLOTS,
        op_ready, /* validate */
        op_open,
        op_ready, /* refresh */
        op_ready, /* retire */
        op_tick,
        op_ready, /* drive */
        op_cancel,
        op_release,
        op_ready, /* close */
    },
    op_resolve,
};

static const bb_mech_Door DOOR = {
    BB_MECH_DOOR_MAGIC,
    BB_MECH_MECHANISM_VERSION,
    (uint32_t)sizeof(bb_mech_Door),
    (uint32_t)BB_MECH_KindCode_Secret,
    BUSBAR_PLUGIN_KIND_ABI,
    &STATEMENT,
    (const bb_mech_OpsHead *)&OPS,
};

/* THE ONE SYMBOL (BB_MECH_DOOR_SYMBOL). */
DOOR_EXPORT const bb_mech_Door *busbar_plugin_door(void) {
    return &DOOR;
}
