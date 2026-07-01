/* test_cccc_ambe.c — cccc_ambe pack/unpack round-trip and exact bit-layout
 * per formal spec §6.2: "bits 0-47 occupy bytes 0-5, bit 48 occupies the
 * most-significant bit of byte 6, and the remaining 7 bits of byte 6 are
 * zero padding." */
#include <stdio.h>
#include <string.h>
#include "../cccc/cccc_ambe.h"

static int fails = 0, checks = 0;

static void check(const char *what, int cond)
{
    checks++;
    if (!cond) { fails++; fprintf(stderr, "FAIL: %s\n", what); }
}

int main(void)
{
    /* 1. Round-trip: arbitrary bit patterns survive pack -> unpack. */
    dmr_bit in[3][49];
    for (int u = 0; u < 3; u++)
        for (int b = 0; b < 49; b++)
            in[u][b] = (dmr_bit)((u * 7 + b * 3 + 1) % 2);

    uint8_t payload[21];
    cccc_ambe_pack21(in, payload);

    dmr_bit out[3][49];
    cccc_ambe_unpack21(payload, out);

    check("round-trip bits identical", memcmp(in, out, sizeof in) == 0);

    /* 2. Exact byte layout: bit 48 of each unit lands in the MSB of byte 6;
     * the low 7 bits of byte 6 are always zero regardless of input. */
    for (int u = 0; u < 3; u++) {
        const uint8_t *unit = payload + u * 7;
        int expect_msb = in[u][48] ? 1 : 0;
        int got_msb = (unit[6] & 0x80) ? 1 : 0;
        char label[64]; snprintf(label, sizeof label, "unit %d: bit48 -> byte6 MSB", u);
        check(label, got_msb == expect_msb);

        char label2[64]; snprintf(label2, sizeof label2, "unit %d: byte6 low 7 bits zero", u);
        check(label2, (unit[6] & 0x7F) == 0);
    }

    /* 3. All-zero and all-one edge cases pack/unpack cleanly. */
    dmr_bit zeros[3][49]; memset(zeros, 0, sizeof zeros);
    uint8_t pz[21]; cccc_ambe_pack21(zeros, pz);
    uint8_t expect_zero[21]; memset(expect_zero, 0, sizeof expect_zero);
    check("all-zero input -> all-zero payload", memcmp(pz, expect_zero, 21) == 0);

    dmr_bit ones[3][49];
    for (int u = 0; u < 3; u++) for (int b = 0; b < 49; b++) ones[u][b] = 1;
    uint8_t po[21]; cccc_ambe_pack21(ones, po);
    dmr_bit ro[3][49]; cccc_ambe_unpack21(po, ro);
    check("all-one round-trip", memcmp(ones, ro, sizeof ones) == 0);
    for (int u = 0; u < 3; u++) {
        char label[64]; snprintf(label, sizeof label, "unit %d: all-one byte6 == 0x80", u);
        check(label, po[u * 7 + 6] == 0x80);
    }

    printf("cccc_ambe self-test: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
