/*
 * Author Jerry Lundström <jerry@dns-oarc.net>
 * Copyright (c) 2016-2017, OARC, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "pcap_thread.h"

#ifndef __pcap_thread_ext_stream_h
#define __pcap_thread_ext_stream_h

#ifdef __cplusplus
extern "C" {
#endif

/*
CONF:
- max streams
- max segments per stream
MODES:
- reassembled: Reassemble the stream before pushing to callback
- ordered: Push segments to callback in order of sequence
- arrival: Push segments to callback as they arrive
OPTIONS:
- need_syn: Need to see SYN, implies need_ack
- need_ack: Need to see ACK for segments

TODO:
- callback for syn/start?
- callback for reset?
- reassemble segments into new buffer or give list of segments
*/

typedef void (*pcap_thread_ext_stream_callback_t)(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length);

/* clang-format off */
#define PCAP_THREAD_EXT_STREAM_CONF_T_INIT { \
    1, 0, \
    0 \
}
/* clang-format on */

typedef struct pcap_thread_ext_stream_conf pcap_thread_ext_stream_conf_t;
struct pcap_thread_ext_stream_conf {
    unsigned short need_syn_ack : 1;
    unsigned short ignore_push : 1;

    pcap_thread_ext_stream_callback_t callback;
};

pcap_thread_ext_stream_conf_t* pcap_thread_ext_stream_conf_new(void);
void pcap_thread_ext_stream_conf_free(pcap_thread_ext_stream_conf_t* conf);

pcap_thread_layer_callback_stream_t pcap_thread_ext_stream_layer_callback(pcap_thread_ext_stream_conf_t* conf);

#ifdef __cplusplus
}
#endif

#endif /* __pcap_thread_ext_stream_h */
