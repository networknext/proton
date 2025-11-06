[![Build Status](https://networknext.semaphoreci.com/badges/proton/branches/master.svg?style=shields&key=1e07ad28-fbe5-42cb-8fe0-60b5286b7949)](https://networknext.semaphoreci.com/projects/proton)

<img width="1102" height="616" alt="image" src="https://github.com/user-attachments/assets/e6827e0e-ae18-4a73-af42-3253558e424c" />

# proton

Proton is a linux kernel module based on [libhydrogen](https://github.com/jedisct1/libhydrogen) that provides crypto functions callable from XDP programs

# Why?

Because I'm crazy and I write highly performant network components and backends in XDP, and I need access to crypto functions to make those work. Maybe you're crazy too?

# Usage

Run `./install.sh` to build and install the kernel module and set it to load on boot.

Now you can include proton.h in your XDP programs and call crypto functions like this:

```
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

extern int proton_sha256( void * data, int data__sz, void * output, int output__sz );

extern int proton_sign_create( void * data, int data__sz, void * signature, int signature__sz, struct proton_sign_create_args * args );

extern int proton_sign_verify( void * data, int data__sz, void * signature, int signature__sz, struct proton_sign_verify_args * args );

extern int proton_secretbox_encrypt( void * data, int data__sz, __u64 message_id, void * key, int key__sz );

extern int proton_secretbox_decrypt( void * data, int data__sz, __u64 message_id, void * key, int key__sz );
```

These functions are compatible with crypto done in userspace using the regular libhydrogen, but please take special care with secretbox because I had to change the function signature.

The reason is that there is a limit of 5 arguments per-kfunc *and* you need to pass in array lengths via *__sz for the BPF verifier.

Because of this, the secretbox functions encrypt and decrypt in-place *and* you need to pass in a pointer to the data with the crypto header included at the front for both encrypt and decrypt.

# Example

If you'd like to see an example of proton in action take a look at the new Network Next backend I'm writing in XDP: https://github.com/networknext/protect
