#ifndef __STRONG_ATTACKER_H
#define __STRONG_ATTACKER_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern uint64_t secret;
extern bool     option_tty;

#define error(msg, ...)                                                 \
    do                                                                  \
    {                                                                   \
        fprintf(stderr, "%serror%s: %s: %u: " msg "\n",                 \
            (option_tty? "\33[31m": ""),                                \
            (option_tty? "\33[0m" : ""),                                \
            __FILE__, __LINE__,                                         \
            ##__VA_ARGS__);                                             \
        abort();                                                        \
    }                                                                   \
    while (false)

extern void check(const uint64_t *p);

#endif
