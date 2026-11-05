/* SPDX-License-Identifier: Apache-2.0 */
/* A focused lifecycle/schema probe. Build with busbar_secret_c.c and the contract header. */
#include "busbar_plugin.h"
#include <stdio.h>
#include <string.h>

const bb_mech_Door *busbar_plugin_door(void);

int main(int argc, char **argv) {
    const bb_mech_Door *door = busbar_plugin_door();
    if (argc == 2 && strcmp(argv[1], "--schema") == 0) {
        const bb_mech_Blob *schema = &door->statement->settings_schema;
        if (schema->fmt != BB_MECH_BLOB_JSON || schema->flags != 0 || schema->ptr == NULL ||
            schema->len == 0) {
            return 2;
        }
        return fwrite(schema->ptr, 1, schema->len, stdout) == schema->len ? 0 : 2;
    }
    if (argc == 3 && strcmp(argv[1], "--validate") == 0) {
        bb_mech_ValidateIn in;
        bb_mech_OutHead out;
        unsigned char error[256];
        memset(&in, 0, sizeof in);
        memset(&out, 0, sizeof out);
        in.head.size = sizeof in;
        in.settings.ptr = (const uint8_t *)argv[2];
        in.settings.len = strlen(argv[2]);
        in.settings.fmt = BB_MECH_BLOB_JSON;
        in.err_buf = error;
        in.err_cap = sizeof error;
        out.size = sizeof out;
        door->ops->validate(NULL, &in, &out);
        return out.outcome == BB_MECH_Outcome_Ready ? 0 : 1;
    }
    return 2;
}
