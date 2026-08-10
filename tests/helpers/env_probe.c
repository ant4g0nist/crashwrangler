// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

static const char *value_or_unset(const char *name) {
    const char *value = getenv(name);
    return value == NULL ? "<unset>" : value;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    FILE *output = fopen(argv[1], "w");
    if (output == NULL) {
        return 3;
    }

    fprintf(output, "CW_PROBE=%s\n", value_or_unset("CW_PROBE"));
    fprintf(output, "CHILD_ONLY=%s\n", value_or_unset("CHILD_ONLY"));
    fprintf(output, "CWE_CW_PROBE=%s\n", value_or_unset("CWE_CW_PROBE"));
    fprintf(output, "MALLOC_FILL_SPACE=%s\n", value_or_unset("MALLOC_FILL_SPACE"));
    fprintf(output, "DYLD_INSERT_LIBRARIES=%s\n",
            value_or_unset("DYLD_INSERT_LIBRARIES"));
    return fclose(output) == 0 ? 0 : 4;
}
