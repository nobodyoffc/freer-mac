#ifndef COPUS_SHIM_H
#define COPUS_SHIM_H

#include "opus.h"

/* opus_encoder_ctl and opus_decoder_ctl are variadic, which Swift cannot
   call: one fixed-signature setter each, for the requests that take an int. */
int copus_encoder_set(OpusEncoder *enc, int request, int value);
int copus_decoder_set(OpusDecoder *dec, int request, int value);

#endif
