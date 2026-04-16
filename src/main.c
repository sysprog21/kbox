/* SPDX-License-Identifier: MIT */

/* kbox entry point: parse CLI arguments and boot the rootfs image. */

#include "kbox/cli.h"
#include "kbox/image.h"

int main(int argc, char *argv[])
{
    struct kbox_image_args args;

    if (kbox_parse_args(argc, argv, &args) < 0)
        return 1;

    return kbox_run_image(&args) < 0 ? 1 : 0;
}
