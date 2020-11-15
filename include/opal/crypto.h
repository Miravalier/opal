#ifndef _OPAL_CRYPTO_H
#define _OPAL_CRYPTO_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <sodium.h>

#define CRYPTO_PACKET_MAX       4096
#define CRYPTO_LENGTH_BYTES     2
#define CRYPTO_HEADER_SIZE      (crypto_box_NONCEBYTES + CRYPTO_LENGTH_BYTES)


typedef uint8_t private_key_t[crypto_box_SECRETKEYBYTES];
typedef uint8_t public_key_t[crypto_box_PUBLICKEYBYTES];

typedef enum crypto_channel_status_e {
    CHANNEL_SUCCESS = 0,
    CHANNEL_ERROR = -1,
    CHANNEL_READ_WAIT = -2,
    CHANNEL_WRITE_WAIT = -3,
} crypto_channel_status_e;

typedef enum crypto_operation_e {
    NO_OP,
    WRITE_OP,
    READ_OP,
    CONNECT_WRITE_OP,
    CONNECT_READ_OP,
} crypto_operation_e;

typedef struct crypto_channel_t {
    // Underlying fd
    int fd;
    // Current operation, for nonblocking channels
    crypto_operation_e operation;
    // Key material
    bool key_compare;
    private_key_t private_key;
    public_key_t local_public_key;
    public_key_t remote_public_key;
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    // Plaintext Buffer
    union {
        uint8_t plaintext[CRYPTO_PACKET_MAX];
        public_key_t temporary_public_key_buffer;
    };
    size_t plaintext_length;
    // Ciphertext Buffer
    struct {
        uint8_t ciphertext[0];
        uint16_t ciphertext_network_length;
        uint8_t ciphertext_nonce[crypto_box_NONCEBYTES];
        uint8_t ciphertext_data[CRYPTO_PACKET_MAX + crypto_box_MACBYTES];
    } __attribute__((packed));
    size_t ciphertext_length;
    size_t ciphertext_processed;
    // Leftover data from an incoming chunk, waiting to be consumed
    // with crypto_channel_read()
    uint8_t unread_data[CRYPTO_PACKET_MAX];
    size_t unread_data_start;
    size_t unread_data_end;
    // Current read and write buffers for crypto_channel_continue()
    union {
        const char *write_buffer;
        char *read_buffer;
    };
    union {
        size_t write_total;
        size_t read_total;
    };
    union {
        size_t write_processed;
        size_t read_processed;
    };
} crypto_channel_t;


/**
 * @brief   Generates a public and private keypair.
 */
void crypto_generate_keys(void *public_key, void *private_key);

/**
 * @brief   Generates a public key derived from a given private key.
 */
void crypto_generate_public_key(void *public_key, const void *private_key);

/**
 * @brief   Allocates memory for and returns a crypto_channel_t. The returned channel
 *          must be freed by the caller.
 */
crypto_channel_t *crypto_channel_new(int fd, const void *private_key, const void *public_key);

/**
 * @brief   Zeroes keys and releases the resources associated with a crypto_channel_t
 *          returned from crypto_channel_new() and deallocates the memory.
 * 
 * @warning Does NOT close or do anything to the underlying fd.
 */
void crypto_channel_free(crypto_channel_t *channel);

/**
 * @brief   Prepares a channel for writing and reading by setting its underlying fd and
 *          local key material.
 */
void crypto_channel_init(crypto_channel_t *channel, int fd, const void *private_key, const void *public_key);

/**
 * @brief   Exchange public keys and calculates a shared key. If the public key is provided,
 *          the remote side's public key must match. If NULL, any public key will be accepted.
 * 
 * @return  0 on success, -1 on error, CHANNEL_READ_WAIT if the fd must be polled for reading,
 *          or CHANNEL_WRITE_WAIT if the fd must be polled for writing. If the channel's fd is
 *          blocking, only 0 or -1 will be returned.
 */
int crypto_channel_connect(crypto_channel_t *channel, const void *remote_public_key);

/**
 * @brief   Zeroes keys and releases resources associated with a channel initialized with
 *          crypto_channel_init().
 * 
 * @warning Does NOT close or do anything to the underlying fd.
 */
void crypto_channel_fini(crypto_channel_t *channel);

/**
 * @brief   If the channel is blocking, returns 0 when the entire message has been
 *          sent or -1 if the message cannot be sent. If the channel is nonblocking,
 *          may return CHANNEL_WRITE_WAIT if the underlying fd must be polled for
 *          write before calling crypto_channel_continue().
 * 
 * @return  0 on success, -1 on error, or CHANNEL_WRITE_WAIT as appropriate if the
 *          channel is nonblocking.
 */
int crypto_channel_write(crypto_channel_t *channel, const void *buffer, size_t bytes);

/**
 * @brief   If the channel is blocking, returns 0 when the message has been
 *          received or -1 if an error occured. If the channel is nonblocking,
 *          may return CHANNEL_READ_WAIT if the underlying fd must be polled for
 *          read before calling crypto_channel_continue().
 * 
 * @return  0 on success, -1 on error, or CHANNEL_READ_WAIT as appropriate if the
 *          channel is nonblocking.
 */
int crypto_channel_read(crypto_channel_t *channel, void *buffer, size_t bytes);

/**
 * @return  0 on success, -1 on error, CHANNEL_READ_WAIT if the channel's fd must be polled
 *          for read before calling crypto_channel_continue() again, or CHANNEL_WRITE_WAIT
 *          if the channel's fd must be polled for writing before calling crypto_channel_continue()
 *          again.
 * 
 * @warning crypto_channel_continue() should only be called on channels with nonblocking fd's,
 *          after getting CHANNEL_WRITE_WAIT or CHANNEL_READ_WAIT as a return status from a
*           crypto_channel_write() or crypto_channel_read() call.
 */
int crypto_channel_continue(crypto_channel_t *channel);

#endif
