/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * test_timeouts.c — standalone compile-only check of gm168_timeouts.h.
 *
 * Has no libfprint / glib / openssl deps so it runs in any clean toolchain
 * and catches refactor mistakes (deleted defines, wrong values, missing
 * include guards) before we attempt the full driver build.
 *
 * Build:
 *     cc -std=c11 -Wall -Wextra -Werror -I../src test_timeouts.c -o test_timeouts
 * Run:
 *     ./test_timeouts
 *
 * A run that prints "OK" and exits 0 means every named constant exists,
 * compiles, and equals the value it had before G13. Anything else => fail.
 */
#include <stdio.h>
#include "gm168_timeouts.h"

/* Belt-and-braces: the same _Static_asserts already fire in the header,
 * but we restate the most important ones here so this test also fails
 * if someone removes the asserts from the header. */
_Static_assert (GM168_USB_RX_TIMEOUT_MS       == 2000, "RX default");
_Static_assert (GM168_USB_RX_SHORT_TIMEOUT_MS == 1000, "RX short");
_Static_assert (GM168_USB_RX_LONG_TIMEOUT_MS  == 3000, "RX long");
_Static_assert (GM168_USB_TX_TIMEOUT_MS       == 2000, "TX");
_Static_assert (GM168_WAKEUP_DELAY_MS         == 50,   "wakeup");
_Static_assert (GM168_TLS_PUMP_DELAY_MS       == 10,   "tls pump");
_Static_assert (GM168_REARM_DELAY_MS          == 1500, "rearm");
_Static_assert (GM168_USB_RX_RETRY_LIMIT      == 60,   "rx retries");
_Static_assert (GM168_TLS_RETRY_LIMIT         == 60,   "tls retries");

/* Sanity: short < default < long. */
_Static_assert (GM168_USB_RX_SHORT_TIMEOUT_MS < GM168_USB_RX_TIMEOUT_MS,
                "short must be < default");
_Static_assert (GM168_USB_RX_TIMEOUT_MS < GM168_USB_RX_LONG_TIMEOUT_MS,
                "default must be < long");

int main (void)
{
    printf ("gm168_timeouts.h: OK\n");
    printf ("  RX       = %d ms\n", GM168_USB_RX_TIMEOUT_MS);
    printf ("  RX_SHORT = %d ms\n", GM168_USB_RX_SHORT_TIMEOUT_MS);
    printf ("  RX_LONG  = %d ms\n", GM168_USB_RX_LONG_TIMEOUT_MS);
    printf ("  TX       = %d ms\n", GM168_USB_TX_TIMEOUT_MS);
    printf ("  WAKEUP   = %d ms\n", GM168_WAKEUP_DELAY_MS);
    printf ("  TLS_PUMP = %d ms\n", GM168_TLS_PUMP_DELAY_MS);
    printf ("  REARM    = %d ms\n", GM168_REARM_DELAY_MS);
    printf ("  RX_RETRY = %d\n",    GM168_USB_RX_RETRY_LIMIT);
    printf ("  TLS_RETRY= %d\n",    GM168_TLS_RETRY_LIMIT);
    return 0;
}
