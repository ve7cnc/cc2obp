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

    /* 2. Byte layout: the wire's bit 48 (MSB of byte 6) carries dmr_utils3 bit
     * PERM[48]=35 because of the c-Bridge 3-lane interleave (cccc_ambe.c); the
     * low 7 bits of byte 6 are always zero regardless of input. */
    for (int u = 0; u < 3; u++) {
        const uint8_t *unit = payload + u * 7;
        int expect_msb = in[u][35] ? 1 : 0;           /* PERM[48] = 35 */
        int got_msb = (unit[6] & 0x80) ? 1 : 0;
        char label[64]; snprintf(label, sizeof label, "unit %d: wire bit48 = DSP bit 35", u);
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

    /* 4. Golden real-data vector: one matched frame from the paired capture
     * dmr/pair_fwd_20260702.pcap. Form B is the exact 7-byte CC-CC wire unit;
     * Form A is the aligned IPSC (dmr_utils3-order) frame, packed 7 bytes
     * MSB-first with bit 48 in byte6 MSB. unpack21(B) must yield A, and
     * pack21(A) must yield B — proving the interleave against the real c-Bridge,
     * not against a copy of our own table. */
    const uint8_t formB_unit[7] = {0xaa,0x02,0xdd,0x8a,0x72,0x50,0x00};
    const uint8_t formA_pack[7] = {0xa1,0xb3,0x11,0x94,0x08,0xf1,0x80};
    dmr_bit formA[49];
    for (int b = 0; b < 48; b++) formA[b] = (dmr_bit)((formA_pack[b / 8] >> (7 - (b % 8))) & 1);
    formA[48] = (formA_pack[6] & 0x80) ? 1 : 0;

    uint8_t gin[21];
    for (int u = 0; u < 3; u++) memcpy(gin + u * 7, formB_unit, 7);   /* 3x the same wire unit */
    dmr_bit gout[3][49];
    cccc_ambe_unpack21(gin, gout);
    int unpack_ok = 1;
    for (int u = 0; u < 3; u++) if (memcmp(gout[u], formA, sizeof formA) != 0) unpack_ok = 0;
    check("golden: unpack21(FormB) == FormA (real c-Bridge frame)", unpack_ok);

    dmr_bit gA[3][49];
    for (int u = 0; u < 3; u++) memcpy(gA[u], formA, sizeof formA);
    uint8_t gwire[21];
    cccc_ambe_pack21(gA, gwire);
    int pack_ok = 1;
    for (int u = 0; u < 3; u++) if (memcmp(gwire + u * 7, formB_unit, 7) != 0) pack_ok = 0;
    check("golden: pack21(FormA) == FormB (real c-Bridge frame)", pack_ok);

    printf("cccc_ambe self-test: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
