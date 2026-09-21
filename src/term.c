/*
 * term.c - deciding whether stdout wants color. The only platform-specific
 * code in Loupe.
 */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* getenv */
#endif

#include "term.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>

/* Declared by hand to keep <windows.h> (and its warnings) out of the build.
 * These match the prototypes in consoleapi.h. */
__declspec(dllimport) int __stdcall GetConsoleMode(void *console, unsigned long *mode);
__declspec(dllimport) int __stdcall SetConsoleMode(void *console, unsigned long mode);
#define ENABLE_VT_PROCESSING 0x0004u

static bool is_terminal(FILE *f)
{
    int fd = _fileno(f);
    if (fd < 0 || !_isatty(fd))
        return false;
    void *h = (void *)_get_osfhandle(fd);
    unsigned long mode;
    if (!GetConsoleMode(h, &mode))
        return false;
    /* Windows 10+ consoles understand ANSI escapes once asked to. */
    return (mode & ENABLE_VT_PROCESSING) || SetConsoleMode(h, mode | ENABLE_VT_PROCESSING);
}
#else
#include <unistd.h>

static bool is_terminal(FILE *f)
{
    const char *term = getenv("TERM");
    return isatty(fileno(f)) && term && strcmp(term, "dumb") != 0;
}
#endif

bool lp_term_color(FILE *f)
{
    const char *no = getenv("NO_COLOR"); /* https://no-color.org */
    if (no && *no)
        return false;
    return is_terminal(f);
}
