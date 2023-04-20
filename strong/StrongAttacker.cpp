/*
 *
 *  ____  _                            _   _   _             _             
 * / ___|| |_ _ __ ___  _ __   __ _   / \ | |_| |_ __ _  ___| | _____ _ __ 
 * \___ \| __| '__/ _ \| '_ \ / _` | / _ \| __| __/ _` |/ __| |/ / _ \ '__|
 *  ___) | |_| | | (_) | | | | (_| |/ ___ \ |_| || (_| | (__|   <  __/ |   
 * |____/ \__|_|  \___/|_| |_|\__, /_/   \_\__|\__\__,_|\___|_|\_\___|_|   
 *                            |___/                         MICROBENCHMARKS     
 *
 * This is a simple microbenchmark suite designed to break most memory error
 * defenses.  We model a strong attacker who can:
 * (1) Can construct arbitrary pointers (p+k) for any k, or retain dangling
 *     pointers
 * (2) Can dereference the invalid pointer from (1)
 * (3) Assumes the target is within the "neighbourhood" of p
 *     (almost always true with most heap allocators).
 * (4) Can RETRY attacks, even if the previous attack were unsuccessful.
 *     E.g., see threat model from "Hacking Blind", USENIX SECURITY 2014.
 */

#include <unistd.h>
#include <sys/syscall.h> 
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "StrongAttacker.h"

#define NOINLINE                __attribute__((__noinline__))

#ifndef PAGE_SIZE
#define PAGE_SIZE   4096
#endif

#define DEFAULT_SIZE                8ul             // Default object size
#define DEFAULT_SPRAY               1ul             // Default heap spray
#define DEFAULT_ATTEMPTS            10000ul         // Default # of attempts

#define EXIT_SECRET_FOUND           111             // Secret found

uint64_t secret              = 0;
static const uint64_t *ptr64 = NULL;                // Start of microbench obj
static const uint64_t *end64 = NULL;                // End of microbench obj
static int null_fd           = 0;
bool option_tty              = false;
static bool option_quiet     = false;
static bool option_verbose   = false;

/*
 * External tests.
 */
size_t cve_2007_3476_size(void);
void cve_2007_3476_init(void *);
void cve_2007_3476(size_t i, bool alt);
size_t cve_2012_4295_size(void);
void cve_2012_4295_init(void *);
void cve_2012_4295(size_t i, bool alt);
size_t cve_2016_1903_size(void);
void cve_2016_1903_init(void *);
void cve_2016_1903(size_t i, bool alt);
size_t cve_2016_2335_size(void);
void cve_2016_2335_init(void *);
void cve_2016_2335(size_t i, bool alt);

#define pass(attempt, msg, ...)                                         \
    do                                                                  \
    {                                                                   \
        if (!option_quiet)                                              \
        {                                                               \
            printf("%spass%s: %zu: " msg "\n",                          \
                (option_tty? "\33[32m": ""),                            \
                (option_tty? "\33[0m" : ""),                            \
                attempt, ##__VA_ARGS__);                                \
        }                                                               \
    }                                                                   \
    while (false)
#define fail(ptr, msg, ...)                                             \
    do                                                                  \
    {                                                                   \
        printf("%sFAIL%s: %zu: " msg "\n",                              \
            (option_tty? "\33[31m": ""),                                \
            (option_tty? "\33[0m" : ""),                                \
            attempt, ##__VA_ARGS__);                                    \
    }                                                                   \
    while (false)

/*
 * Test type.
 */
enum TEST
{
    NONE,
    OVERFLOW,
    UNDERFLOW,
    OOB,            // OVERFLOW | UNDERFLOW
    UAF,            // Use-after-free
    CVE_2007_3476,
    CVE_2012_4295,
    CVE_2016_1903,
    CVE_2016_2335,
};

/*
 * Check if dereferencing the given pointer will access a target.  If so, exit
 * with EXIT_SECRET_FOUND exit code.
 */
NOINLINE void check(const uint64_t *p)
{
    fprintf(stderr, "CHECK %p\n", p);
    register uint64_t s = ~secret;
    if (*p == s)
        exit(EXIT_SECRET_FOUND);
}

/*
 * Perform an attack.  This function ignores any error or crash, as it models
 * that case where the attacker can retry after an unsuccessful attempt.
 *
 * NOTE: This function assumes that any memory error defense crashes or
 *       aborts.  The defense may need to be configured accordingly. or
 *       this function may need to be adapted to the defense.
 */
static NOINLINE void do_attack(size_t attempt, bool alt, enum TEST test)
{
    switch (test)
    {
        case OVERFLOW: case UNDERFLOW: case UAF:
            if (alt)
                return;
            break;
        default:
            break;
    }

    pid_t child = fork();
    if (child == 0)
    {
        if (!option_verbose)
        {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
        }
        const uint64_t *p = NULL;
        switch (test)
        {
            case CVE_2007_3476:
                cve_2007_3476(attempt, alt); break;
            case CVE_2012_4295:
                cve_2012_4295(attempt, alt); break;
            case CVE_2016_1903:
                cve_2016_1903(attempt, alt); break;
            case CVE_2016_2335:
                cve_2016_2335(attempt, alt); break;
            default:
                // Microbenchmarks:
                switch (test)
                {
                    case OOB:       p = (alt? ptr64 - 1 - attempt:
                                              end64 + 1 + attempt); break;
                    case OVERFLOW : p = end64 + 1 + attempt; break;
                    case UNDERFLOW: p = ptr64 - 1 - attempt; break;
                    case UAF:       p = ptr64; break;
                    default:        break;
                }
                check(p);
                break;
        }
        exit(EXIT_SUCCESS);
    }
    else if (child < 0)
  		error("failed to fork child process: %s", strerror(errno));      

    int status;
	if (waitpid(child, &status, 0) < 0)
        error("failed to wait for child process: %s", strerror(errno));

    if (WIFEXITED(status))
    {
        int code = WEXITSTATUS(status);
        if (code == EXIT_SECRET_FOUND)
        {
        	fail(attempt, "secret 0x%.16lx found", ~secret);
            exit(EXIT_FAILURE);
        }
        else
            pass(attempt, "secret not found [code=%d]", code);
    }
    else if (WIFSIGNALED(status))
    {
        int sig = WTERMSIG(status);
        pass(attempt, "secret not found [signal=%s]", strsignal(sig));
    }
}
static NOINLINE void attack(size_t attempt, enum TEST test)
{
    do_attack(attempt, /*alt=*/false, test);
    do_attack(attempt, /*alt=*/true,  test);
}

/*
 * Allocate a target.
 */
static void *malloc_target(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL)
        error("failed to malloc %zu bytes: %s", size, strerror(errno));
    uint64_t *ptr64 = (uint64_t *)ptr;
    for (size_t i = 0; i < size / sizeof(uint64_t); i++)
        ptr64[i] = ~secret;
    return ptr;
}

/*
 * Usage message.
 */
static void usage(const char *progname)
{
    fprintf(stderr,
        "usage: %s [OPTIONS] TEST\n"
        "\n"
        "OPTIONS:\n"
        "\t--size N, -s N\n"
        "\t\tTarget size in bytes (default: %zu)\n"
        "\t--spray N, -n N\n"
        "\t\tNumber of targets (default: %zu)\n"
        "\t--attempts N, -a N\n"
        "\t\tNumber of attack attempts (default: %zu)\n"
        "\t--quiet, -q\n"
        "\t\tPrint less output\n"
        "\t--verbose, -v\n"
        "\t\tPrint more output\n"
        "\t--help, -h\n"
        "\t\tPrint this message\n"
        "\n"
        "TEST:\n"
        "\toverflow\n"
        "\t\tOverflow microbenchmark\n"
        "\tunderflow\n"
        "\t\tUnderflow microbenchmark\n"
        "\toob\n"
        "\t\tOverflow and underflow microbenchmark\n"
        "\tuaf\n"
        "\t\tUse-after-free microbenchmark\n"
        "\tcve-2007-3476\n"
        "\tcve-2012-4295\n"
        "\tcve-2016-1903\n"
        "\tcve-2016-2335\n"
        "\t\tCorresponding CVE\n",
        progname,
        DEFAULT_SIZE,
        DEFAULT_SPRAY,
        DEFAULT_ATTEMPTS);
    exit(EXIT_FAILURE);
}

/*
 * Entry.
 */
int main(int argc, char **argv)
{
    option_tty = (isatty(STDOUT_FILENO) != 0);
    size_t size     = DEFAULT_SIZE;
    size_t spray    = DEFAULT_SPRAY;
    size_t attempts = DEFAULT_ATTEMPTS;
    static const struct option long_options[] =
    {
        {"size",     required_argument, NULL, 's'},
        {"spray",    required_argument, NULL, 'n'},
        {"attempts", required_argument, NULL, 'a'},
        {"quiet",    no_argument,       NULL, 'q'},
        {"verbose",  no_argument,       NULL, 'v'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,       no_argument,       NULL, 0}
    };
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "s:n:a:qvh", long_options,
            &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case 's':
                size = strtoull(optarg, NULL, 0); break;
            case 'n':
                spray = strtoull(optarg, NULL, 0); break;
            case 'a':
                attempts = strtoull(optarg, NULL, 0); break;
            case 'q':
                option_quiet = true; break;
            case 'v':
                option_verbose = true; break;
            case 'h': default:
                usage(argv[0]);
        }
    }
    if (optind != argc-1)
        usage(argv[0]);

    const char *teststr = argv[optind];
    enum TEST test = NONE;
    if (strcmp(teststr, "overflow") == 0)
        test = OVERFLOW;
    else if (strcmp(teststr, "underflow") == 0)
        test = UNDERFLOW;
    else if (strcmp(teststr, "oob") == 0)
        test = OOB;
    else if (strcmp(teststr, "uaf") == 0)
        test = UAF;
    else if (strcmp(teststr, "cve-2007-3476") == 0)
    {
        test = CVE_2007_3476;
        size = cve_2007_3476_size();
    }
    else if (strcmp(teststr, "cve-2012-4295") == 0)
    {
        test = CVE_2012_4295;
        size = cve_2012_4295_size();
    }
    else if (strcmp(teststr, "cve-2016-1903") == 0)
    {
        test = CVE_2016_1903;
        size = cve_2016_1903_size();
    }
    else if (strcmp(teststr, "cve-2016-2335") == 0)
    {
        test = CVE_2016_2335;
        size = cve_2016_2335_size();
    }
    if (test == NONE)
        usage(argv[0]);
    if (test == OVERFLOW || test == UNDERFLOW)
        error("the underflow/overflow tests are disabled; use \"oob\" instead");

    if (size < sizeof(uint64_t))
        error("target size must be greater than %zu bytes; found %zu",
            sizeof(uint64_t), size);
    if (spray < 1)
        error("target spray must be greater than 0; found %zu", spray);
    if (attempts < 1)
        error("attack attempts must be greater than 0; found %zu", attempts);

    // Allocate & initialize targets
    spray++;        // +1 to include one valid object
    while (secret == 0)
        syscall(SYS_getrandom, &secret, sizeof(secret), 0);
    size_t idx = spray / 2;
    void *ptr = mmap(NULL, spray * sizeof(void *), PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED)
        error("failed to map memory: %s", strerror(errno));
    void **ps = (void **)ptr;
    for (size_t i = 0; i < spray; i++)
    {
        ps[i] = malloc_target(size);
        if (i == idx)
        {
            memset(ps[i], 0x0, size);
            switch (test)
            {
                case CVE_2007_3476:
                    cve_2007_3476_init(ps[i]); break;
                case CVE_2012_4295:
                    cve_2012_4295_init(ps[i]); break;
                case CVE_2016_1903:
                    cve_2016_1903_init(ps[i]); break;
                case CVE_2016_2335:
                    cve_2016_2335_init(ps[i]); break;
                default:
                    break;
            }
        }
        else if (option_verbose)
            fprintf(stderr, "TARGET=%p\n", ps[i]);
    }

    // Run tests:
    null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    ptr64 = (const uint64_t *)ps[idx];
    size_t end = size / sizeof(uint64_t);
    end64 = ptr64 + end;
    switch (test)
    {
        case UAF:
        {
            free(ps[idx]);
            ps[idx] = NULL;
            for (size_t i = 0; i < attempts; i++)
            {
                // Allocate a new target each loop.
                // Note: This test will leak memory.
                ps[i % spray] = malloc_target(size);
                attack(i, test);
            }
            break;
        }
        default:
            for (ssize_t i = 0; i < attempts; i++)
                attack(i, test);
            break;
    }

    printf("%spassed%s after %zu attempts\n", 
        (option_tty? "\33[32m": ""),
        (option_tty? "\33[0m": ""), attempts);

    return 0;
}

const char* __asan_default_options() { return "detect_leaks=0:exitcode=0"; }

