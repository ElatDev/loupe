/*
 * fuzz_loupe.c - libFuzzer entry point.
 *
 *   build.bat fuzz
 *   build\fuzz\fuzz_loupe.exe corpus -max_len=65536 -timeout=10
 *
 * The input is wrapped, not copied, so the allocation ends exactly where the
 * input does and any read one byte past it lands in an AddressSanitizer
 * redzone. Output goes to a sink that still formats every line, so the
 * printing code is fuzzed along with the parsing code.
 */
#include <stdint.h>
#include <stdlib.h>

#include "loupe.h"
#include "mem.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    lp_image *img = NULL;
    if (lp_image_wrap(data, size, &img) != LP_OK)
        return 0;

    lp_out out;
    lp_out_null(&out);
    lp_opts opts = {LP_SHOW_ALL, false};
    lp_inspect(img, "fuzz", &opts, &out);
    lp_image_free(img);

    /* Every file must give back everything it took. */
    if (lp_live_allocations() != 0)
        abort();
    return 0;
}
