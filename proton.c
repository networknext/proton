/*
    Proton Linux kernel module. Copyright 2017 - 2025 Network Next, Inc.

    Licensed under the GNU General Public License 3.0

    Tested on Ubuntu 22.04 LTS and Ubuntu 24.04 LTS

    USAGE:

        sudo insmod proton.ko
        lsmod
        sudo dmesg --follow
        sudo rmmod proton

    BTF debugging:

        sudo bpftool btf show
        sudo bpftool btf dump id <id>
*/

#include "proton.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include "hydrogen.h"

// ----------------------------------------------------------------------------------------------------------------------

struct crypto_shash * sha256;

__bpf_kfunc int proton_sha256( void * data, int data__sz, void * output, int output__sz )
{
    SHASH_DESC_ON_STACK( shash, tfm );
    shash->tfm = sha256;
    crypto_shash_digest( shash, data, data__sz, output );
    return 0;
}

// ----------------------------------------------------------------------------------------------------------------------

static __u8 sign_context[hydro_sign_CONTEXTBYTES];

__bpf_kfunc int proton_sign_create( void * data, int data__sz, void * signature, int signature__sz, struct proton_sign_create_args * args )
{
    kernel_fpu_begin();
    int result = hydro_sign_create( signature, data, data__sz, sign_context, args->private_key );
    kernel_fpu_end();
    return result;
}

__bpf_kfunc int proton_sign_verify( void * data, int data__sz, void * signature, int signature__sz, struct proton_sign_verify_args * args )
{
    kernel_fpu_begin();
    char context[hydro_sign_CONTEXTBYTES];
    memset( context, 0, sizeof(context) );
    int result = hydro_sign_verify( signature, data, data__sz, sign_context, args->public_key );
    kernel_fpu_end();
    return result;
}

// ----------------------------------------------------------------------------------------------------------------------

static __u8 secretbox_context[hydro_secretbox_CONTEXTBYTES];

int proton_secretbox_encrypt( void * data, int data__sz, __u64 message_id, void * key, int key__sz )
{
    kernel_fpu_begin();
    void * message = data + PROTON_SECRETBOX_CRYPTO_HEADER_BYTES;
    int message_bytes = data__sz - PROTON_SECRETBOX_CRYPTO_HEADER_BYTES;
    int result = hydro_secretbox_encrypt( data, message, message_bytes, message_id, secretbox_context, key );
    kernel_fpu_end();
    return result;
}

int proton_secretbox_decrypt( void * data, int data__sz, __u64 message_id, void * key, int key__sz )
{
    kernel_fpu_begin();
    // ...
    kernel_fpu_end();
    return 0;
}

// ----------------------------------------------------------------------------------------------------------------------

BTF_SET8_START( bpf_task_set )
BTF_ID_FLAGS( func, proton_sha256 )
BTF_ID_FLAGS( func, proton_sign_verify )
BTF_ID_FLAGS( func, proton_sign_create )
BTF_ID_FLAGS( func, proton_secretbox_encrypt )
BTF_ID_FLAGS( func, proton_secretbox_decrypt )
BTF_SET8_END( bpf_task_set )

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &bpf_task_set,
};

// ----------------------------------------------------------------------------------------------------------------------

static int __init proton_init( void ) 
{
    pr_info( "proton kernel module initializing...\n" );

    sha256 = crypto_alloc_shash( "sha256", 0, 0 );
    if ( IS_ERR( sha256 ) )
    {
        pr_err( "can't create sha256 crypto hash algorithm\n" );
        return PTR_ERR( sha256 );
    }

    int result = register_btf_kfunc_id_set( BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set );
    if ( result != 0 )
    {
        pr_err( "failed to register proton kernel module kfuncs\n" );
        return -1;
    }

    pr_info( "proton kernel module initialized successfully\n" );

    return result;
}

static void __exit proton_exit( void ) 
{
    pr_info( "proton kernel module shutting down...\n" );

    if ( !IS_ERR( sha256 ) )
    {
        crypto_free_shash( sha256 );
    }

    pr_info( "proton kernel module shut down successfully\n" );
}

module_init( proton_init );
module_exit( proton_exit );

#include "hydrogen.c"

MODULE_VERSION( "1.0.0" );
MODULE_LICENSE( "GPL" ); 
MODULE_AUTHOR( "Glenn Fiedler" ); 
MODULE_DESCRIPTION( "Proton kernel module. Provides crypto functions that are callable from XDP programs." );
