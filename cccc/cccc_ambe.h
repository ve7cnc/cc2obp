/* cccc_ambe.h — CC-CC 21-byte voice payload <-> 3x49-bit AMBE (spec §6.2).
 * Pure bit-packing; does not touch the AMBE-with-FEC (72-bit) domain — pair
 * with dmr_ambe_49_to_72/dmr_ambe_72_to_49 (dmr/dmr.h) to cross to OpenBridge. */
#ifndef CCCC_AMBE_H
#define CCCC_AMBE_H

#include <stdint.h>
#include "../dmr/dmr.h"

/* Pack three 49-bit AMBE frames into the 21-byte CC-CC RTP payload. */
void cccc_ambe_pack21(const dmr_bit ambe49[3][49], uint8_t out21[21]);

/* Unpack the 21-byte CC-CC RTP payload into three 49-bit AMBE frames. */
void cccc_ambe_unpack21(const uint8_t in21[21], dmr_bit ambe49[3][49]);

#endif /* CCCC_AMBE_H */
