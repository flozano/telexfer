/*
 * x25route - add a Linux kernel X.25 route (test helper):
 *   x25route PREFIX DIGITS DEVICE
 * Calls to X.121 addresses whose first DIGITS digits match PREFIX leave
 * through DEVICE (for example lapb0).  Needs CAP_NET_ADMIN.
 */
#include <stdio.h>
#include <stdlib.h>

#include "x25linux.h"

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: x25route PREFIX DIGITS DEVICE\n");
        return 2;
    }
    if (kx25_add_route(argv[1], atoi(argv[2]), argv[3]) < 0) {
        fprintf(stderr, "x25route: %s\n", get_error());
        return 1;
    }
    return 0;
}
