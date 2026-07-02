/* cccc_ambe.c — see cccc_ambe.h.
 *
 * Byte packing (formal spec §6.2): within each 7-byte unit the 49-bit frame is
 * packed most-significant-bit first — bits 0-47 in bytes 0-5, bit 48 in the MSB
 * of byte 6, low 7 bits of byte 6 zero.
 *
 * Bit ORDER (NOT in any spec — empirically derived 2026-07-02 from a paired
 * IPSC-vs-CC-CC capture of one keyup, tools/ambe_convention_diff.py over 657
 * frame pairs, capture saved as dmr/pair_fwd_20260702.pcap): the c-Bridge does
 * NOT carry the 49 bits in dmr_utils3/IPSC order. It carries a fixed 3-lane
 * block interleave of them — write the dmr_utils3-order bits across 3 rows of
 * length 18/18/13, then read down the columns. The c-Bridge has no AMBE codec
 * (it needs an external AMBE3000 to touch audio), so this is pure bit
 * reformatting, not a vocoder transform.  CCCC_AMBE_PERM[j] = the dmr_utils3
 * bit index carried in wire position j, i.e. WIRE[j] = DSP[PERM[j]].  We map to
 * dmr_utils3 order on unpack (so dmr_ambe_49_to_72 sees what it expects) and
 * back to c-Bridge order on pack. */
#include "cccc_ambe.h"
#include <string.h>

/* WIRE[j] = DSP[PERM[j]] — column-major read of the 18/18/13 row grid. */
static const int CCCC_AMBE_PERM[49] = {
     0,18,36, 1,19,37, 2,20,38, 3,21,39, 4,22,40, 5,23,41, 6,24,42,
     7,25,43, 8,26,44, 9,27,45,10,28,46,11,29,47,12,30,48,13,31,14,
    32,15,33,16,34,17,35
};

void cccc_ambe_pack21(const dmr_bit ambe49[3][49], uint8_t out21[21])
{
    for (int i = 0; i < 3; i++) {
        dmr_bit wire[49];                             /* c-Bridge lane order */
        for (int j = 0; j < 49; j++) wire[j] = ambe49[i][CCCC_AMBE_PERM[j]];
        uint8_t *unit = out21 + i * 7;
        dmr_bits_to_bytes(wire, 48, unit);            /* bits 0..47 -> bytes 0..5 */
        unit[6] = wire[48] ? 0x80 : 0x00;             /* bit 48 -> MSB of byte 6, rest zero */
    }
}

void cccc_ambe_unpack21(const uint8_t in21[21], dmr_bit ambe49[3][49])
{
    for (int i = 0; i < 3; i++) {
        const uint8_t *unit = in21 + i * 7;
        dmr_bit wire[49];                             /* c-Bridge lane order */
        dmr_bytes_to_bits(unit, 6, wire);             /* bytes 0..5 -> bits 0..47 */
        wire[48] = (unit[6] & 0x80) ? 1 : 0;
        for (int j = 0; j < 49; j++) ambe49[i][CCCC_AMBE_PERM[j]] = wire[j];  /* -> dmr_utils3 order */
    }
}
