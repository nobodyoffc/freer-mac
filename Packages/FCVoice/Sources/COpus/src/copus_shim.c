#include "copus_shim.h"

int copus_encoder_set(OpusEncoder *enc, int request, int value) {
    return opus_encoder_ctl(enc, request, value);
}

int copus_decoder_set(OpusDecoder *dec, int request, int value) {
    return opus_decoder_ctl(dec, request, value);
}
