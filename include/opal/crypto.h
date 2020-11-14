#ifndef _OPAL_CRYPTO_H
#define _OPAL_CRYPTO_H

#include <stdlib.h>
#include <stdint.h>
#include <nacl/crypto_box.h>
#include <nacl/crypto_secretbox.h>

#define CRYPTO_PACKET_MAX       4096
#define CRYPTO_LENGTH_BYTES     2
#define CRYPTO_HEADER_SIZE      (crypto_secretbox_NONCEBYTES + CRYPTO_LENGTH_BYTES)


typedef uint8_t local_key_t[crypto_box_SECRETKEYBYTES];
typedef uint8_t remote_key_t[crypto_box_PUBLICKEYBYTES];

typedef enum crypto_operation_e {
    NO_OP,
    WRITE_OP,
    READ_OP,
} crypto_operation_e;

typedef enum crypto_channel_status_e {
    CHANNEL_SUCCESS = 0,
    CHANNEL_ERROR = -1,
    CHANNEL_READ_WAIT = -2,
    CHANNEL_WRITE_WAIT = -3,
} crypto_channel_status_e;

typedef struct crypto_channel_t {
    // Underlying fd
    int fd;
    // Current operation, for nonblocking channels
    crypto_operation_e operation;
    // Key material
    uint8_t key[crypto_box_BEFORENMBYTES];
    // Plaintext Buffer
    struct {
        uint8_t plaintext_zeroes[crypto_box_ZEROBYTES];
        union {
            // Size 0 arrays are forbidden by ISO C
            uint8_t plaintext[1];
            uint8_t plaintext_data[CRYPTO_PACKET_MAX];
        };
    } __attribute__((packed));
    size_t plaintext_length;
    // Ciphertext Buffer
    struct {
        union {
#if crypto_box_NONCEBYTES + CRYPTO_LENGTH_BYTES > crypto_box_BOXZEROBYTES
            struct {
                union {
                    // Size 0 arrays are forbidden by ISO C
                    uint8_t ciphertext[1];
                    uint16_t ciphertext_network_length;
                };
                uint8_t ciphertext_nonce[crypto_box_NONCEBYTES];
            } __attribute__((packed));
            struct {
                uint8_t ciphertext_padding[(crypto_box_NONCEBYTES + CRYPTO_LENGTH_BYTES) - crypto_box_BOXZEROBYTES];
                uint8_t ciphertext_zeroes[crypto_box_BOXZEROBYTES];
            } __attribute__((packed));
#else
            uint8_t ciphertext_zeroes[crypto_box_BOXZEROBYTES];
            struct {
                uint8_t ciphertext_padding[crypto_box_BOXZEROBYTES - (crypto_box_NONCEBYTES + CRYPTO_LENGTH_BYTES)];
                struct {
                    union {
                        uint8_t ciphertext[0];
                        uint16_t ciphertext_network_length;
                    };
                    uint8_t ciphertext_nonce[crypto_box_NONCEBYTES];
                } __attribute__((packed));
            } __attribute__((packed));
#endif
        };
        uint8_t ciphertext_data[CRYPTO_PACKET_MAX];
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
 * @brief   Generates the local and remote side of a key.
 */
void crypto_generate_keys(local_key_t *local, remote_key_t *remote);

/**
 * @brief   Prepares a channel for writing and reading by setting its underlying fd and
 *          key material.
 */
void crypto_channel_init(crypto_channel_t *channel, int fd, const local_key_t *local_key, const remote_key_t *remote_key);

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