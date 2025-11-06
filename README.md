<img width="1102" height="616" alt="image" src="https://github.com/user-attachments/assets/e6827e0e-ae18-4a73-af42-3253558e424c" />

# proton

Proton is a linux kernel module based on [libhydrogen](https://github.com/jedisct1/libhydrogen) that provides crypto functions callable from XDP programs

# Why?

Because I'm crazy and I write highly performant network components and backends in XDP, and I need access to crypto functions to make those work. Maybe you're crazy too?

# Usage

Just run `./setup.sh` to build and install the kernel module, and set it to load on boot.

Now you can just include proton.h in your XDP programs and call crypto functions:

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

Please take special care with secretbox because I had to change the way it works (you must pass in pointer to a struct including the crypto header in front, and it will encrypt/decryt in place. This is necessary because there is a limit of 5 arguments per-kfunc and I need to pass in array lengths via *__sz for the BPF verifier.
