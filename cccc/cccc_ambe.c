/* cccc_ambe.c — see cccc_ambe.h.  Formal spec §6.2:
 *   "Within each 7-byte unit the 49-bit frame is packed most-significant-bit
 *    first: bits 0-47 occupy bytes 0-5, bit 48 occupies the most-significant
 *    bit of byte 6, and the remaining 7 bits of byte 6 are zero padding." */
#include "cccc_ambe.h"
#include <string.h>

void cccc_ambe_pack21(const dmr_bit ambe49[3][49], uint8_t out21[21])
{
    for (int i = 0; i < 3; i++) {
        uint8_t *unit = out21 + i * 7;
        dmr_bits_to_bytes(ambe49[i], 48, unit);      /* bits 0..47 -> bytes 0..5 */
        unit[6] = ambe49[i][48] ? 0x80 : 0x00;        /* bit 48 -> MSB of byte 6, rest zero */
    }
}

void cccc_ambe_unpack21(const uint8_t in21[21], dmr_bit ambe49[3][49])
{
    for (int i = 0; i < 3; i++) {
        const uint8_t *unit = in21 + i * 7;
        dmr_bytes_to_bits(unit, 6, ambe49[i]);        /* bytes 0..5 -> bits 0..47 */
        ambe49[i][48] = (unit[6] & 0x80) ? 1 : 0;
    }
}
