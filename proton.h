/*
    Proton Linux kernel module

    Tested on Ubuntu 22.04 LTS and Ubuntu 24.04 LTS

    USAGE:

        sudo insmod proton.ko
        lsmod
        sudo dmesg --follow
        sudo rmmod proton

    BTF debugging:

        sudo bpftool btf show
        sudo bpftool btf dump id <id>

    ISC License:

        Copyright (c) 2025 Network Next, Inc.

        Written by Glenn Fiedler <glenn@networknext.com>

        Permission to use, copy, modify, and/or distribute this software for any
        purpose with or without fee is hereby granted, provided that the above
        copyright notice and this permission notice appear in all copies.
        
        THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
        WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
        MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
        ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
        WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
        ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
        OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#pragma once

#include <linux/types.h>

#ifdef __BPF__
#define PROTON_FUNC __ksym
#else // #ifdef __BPF__
#define PROTON_FUNC 
#endif // #ifdef __BPF__

#define PROTON_SIGN_PUBLIC_KEY_BYTES              32
#define PROTON_SIGN_PRIVATE_KEY_BYTES             64

#define PROTON_SECRETBOX_KEY_BYTES                32
#define PROTON_SECRETBOX_CRYPTO_HEADER_BYTES      36

struct proton_sign_create_args
{
    __u8 private_key[PROTON_SIGN_PRIVATE_KEY_BYTES];
};

struct proton_sign_verify_args
{
    __u8 public_key[PROTON_SIGN_PUBLIC_KEY_BYTES];
};

extern int proton_sha256( void * data, int data__sz, void * output, int output__sz ) PROTON_FUNC;

extern int proton_sign_create( void * data, int data__sz, void * signature, int signature__sz, struct proton_sign_create_args * args ) PROTON_FUNC;

extern int proton_sign_verify( void * data, int data__sz, void * signature, int signature__sz, struct proton_sign_verify_args * args ) PROTON_FUNC;

extern int proton_secretbox_encrypt( void * data, int data__sz, __u64 message_id, void * key, int key__sz ) PROTON_FUNC;

extern int proton_secretbox_decrypt( void * data, int data__sz, __u64 message_id, void * key, int key__sz ) PROTON_FUNC;
