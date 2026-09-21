#ifndef LOUPE_TERM_H
#define LOUPE_TERM_H

#include <stdbool.h>
#include <stdio.h>

/* True if `f` is an interactive terminal that can show ANSI color and the
 * user has not set NO_COLOR. */
bool lp_term_color(FILE *f);

#endif
