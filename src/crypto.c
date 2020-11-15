#include <endian.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sodium.h>

#include "opal/crypto.h"
#include "opal/debug.h"

// Constructor
void __attribute__((constructor)) crypto_channel_constructor(void)
{
    if (sodium_init() == -1)
    {
        opal_error("failed to initialize libsodium");
    }
}


// Static functions
static void crypto_channel_encrypt_chunk(crypto_channel_t *channel)
{
    // Zero the necessary prefix bytes
    bzero(channel->plaintext_zeroes, crypto_box_ZEROBYTES);
    // Generate a nonce
    uint8_t nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, crypto_box_NONCEBYTES);
    // Encrypt the plaintext, storing it into channel->ciphertext_data
    crypto_box_afternm(
        channel->ciphertext_zeroes,
        channel->plaintext_zeroes,
        crypto_box_ZEROBYTES + channel->plaintext_length,
        nonce,
        channel->key
    );
    // Store the ciphertext network length
    channel->ciphertext_network_length = htobe16(channel->plaintext_length);
    // Store the ciphertext nonce
    memcpy(channel->ciphertext_nonce, nonce, crypto_box_NONCEBYTES);
    // Store ciphertext size and zero processed bytes
    channel->ciphertext_length = channel->plaintext_length + CRYPTO_HEADER_SIZE;
    channel->ciphertext_processed = 0;
}


static int crypto_channel_decrypt_chunk(crypto_channel_t *channel)
{
    // Retreive the nonce from the buffer
    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, channel->ciphertext_nonce, crypto_box_NONCEBYTES);
    // Zero the necessary prefix bytes (erasing nonce and network length)
    bzero(channel->ciphertext_zeroes, crypto_box_ZEROBYTES);
    // Perform decryption, putting data into channel->plaintext
    int status = crypto_box_open_afternm(
        channel->plaintext_zeroes,
        channel->ciphertext_zeroes,
        crypto_box_ZEROBYTES + channel->ciphertext_length - CRYPTO_HEADER_SIZE,
        nonce,
        channel->key
    );
    // Store plaintext size and zero processed bytes
    channel->plaintext_length = channel->ciphertext_length - CRYPTO_HEADER_SIZE;
    return status;
}


static int crypto_channel_receive_chunk(crypto_channel_t *channel)
{
    while (channel->ciphertext_processed < channel->ciphertext_length)
    {
        ssize_t bytes_read = read(
                channel->fd,
                channel->ciphertext + channel->ciphertext_processed,
                channel->ciphertext_length - channel->ciphertext_processed);
        if (bytes_read == 0)
        {
            return CHANNEL_ERROR;
        }
        else if (bytes_read == -1)
        {
            if (errno == EAGAIN)
            {
                return CHANNEL_READ_WAIT;
            }
            else
            {
                return CHANNEL_ERROR;
            }
        }
        else
        {
            channel->ciphertext_processed += bytes_read;
            if (channel->ciphertext_processed > CRYPTO_LENGTH_BYTES)
            {
                channel->ciphertext_length = be16toh(channel->ciphertext_network_length) + CRYPTO_HEADER_SIZE;
            }
        }
    }

    return CHANNEL_SUCCESS;
}


static int crypto_channel_send_chunk(crypto_channel_t *channel)
{
    while (channel->ciphertext_processed < channel->ciphertext_length)
    {
        ssize_t bytes_written = write(
                channel->fd,
                channel->ciphertext + channel->ciphertext_processed,
                channel->ciphertext_length - channel->ciphertext_processed);
        if (bytes_written == 0)
        {
            return CHANNEL_ERROR;
        }
        else if (bytes_written == -1)
        {
            if (errno == EAGAIN)
            {
                return CHANNEL_WRITE_WAIT;
            }
            else
            {
                return CHANNEL_ERROR;
            }
        }
        else
        {
            channel->ciphertext_processed += bytes_written;
        }
    }

    return CHANNEL_SUCCESS;
}


static int crypto_channel_write_continue(crypto_channel_t *channel)
{
    // Chunk and send the message until an error, write wait, or done
    while (channel->write_processed < channel->write_total) {
        // Send the previous chunk
        int status = crypto_channel_send_chunk(channel);
        if (status == CHANNEL_ERROR || status == CHANNEL_WRITE_WAIT)
        {
            return status;
        }
        channel->write_processed += channel->plaintext_length;

        // Determine a size for the next chunk
        channel->plaintext_length = MAX(channel->write_total - channel->write_processed, CRYPTO_PACKET_MAX);
        // Move the chunk into the plaintext buffer
        memcpy(channel->plaintext_data, channel->write_buffer + channel->write_processed, channel->plaintext_length);
        // Encrypt the chunk
        crypto_channel_encrypt_chunk(channel);
    }

    channel->operation = NO_OP;
    return CHANNEL_SUCCESS;
}


static int crypto_channel_read_continue(crypto_channel_t *channel)
{
    int status;

    while (channel->read_processed < channel->read_total)
    {
        // Figure out how many bytes are still needed
        size_t bytes_needed = channel->read_total - channel->read_processed;

        // Consume bytes out of the unread data field if there are any
        size_t unread_bytes_available = channel->unread_data_end - channel->unread_data_start;
        if (unread_bytes_available > 0)
        {
            size_t unread_bytes_to_consume = MIN(bytes_needed, unread_bytes_available);
            memcpy(channel->read_buffer, channel->unread_data + channel->unread_data_start, unread_bytes_to_consume);
            channel->read_processed += unread_bytes_to_consume;
            channel->unread_data_start += unread_bytes_to_consume;
            if (channel->read_processed == channel->read_total)
            {
                break;
            }
        }

        // Receive a chunk if more data is needed
        status = crypto_channel_receive_chunk(channel);
        if (status == CHANNEL_ERROR || status == CHANNEL_READ_WAIT)
        {
            return status;
        }
        // Decrypt the chunk
        status = crypto_channel_decrypt_chunk(channel);
        if (status == -1)
        {
            return CHANNEL_ERROR;
        }

        // Calculate the number of bytes from this chunk to consume
        size_t chunk_bytes_available = channel->plaintext_length;
        size_t chunk_bytes_to_consume = MIN(bytes_needed, chunk_bytes_available);
        size_t chunk_bytes_remaining = chunk_bytes_available - chunk_bytes_to_consume;
        // Move the consumed chunk data into the read buffer
        memcpy(channel->read_buffer, channel->plaintext, chunk_bytes_to_consume);
        channel->read_processed += chunk_bytes_to_consume;
        // Store the rest of the chunk data in the unread data field
        if (chunk_bytes_remaining > 0)
        {
            memcpy(channel->unread_data, channel->plaintext + chunk_bytes_to_consume, chunk_bytes_remaining);
        }
        channel->unread_data_start = 0;
        channel->unread_data_end = chunk_bytes_remaining;
    }

    channel->operation = NO_OP;
    return CHANNEL_SUCCESS;
}


// Public functions
void crypto_generate_keys(remote_key_t *remote, local_key_t *local)
{
    crypto_box_keypair((void*)remote, (void*)local);
}


crypto_channel_t *crypto_channel_new(int fd, const local_key_t *local_key, const remote_key_t *remote_key)
{
    crypto_channel_t *channel = malloc(sizeof(crypto_channel_t));
    if (channel == NULL)
    {
        return NULL;
    }
    crypto_channel_init(channel, fd, local_key, remote_key);
    return channel;
}


void crypto_channel_free(crypto_channel_t *channel)
{
    if (channel != NULL)
    {
        crypto_channel_fini(channel);
        free(channel);
    }
}


void crypto_channel_init(crypto_channel_t *channel, int fd, const local_key_t *local_key, const remote_key_t *remote_key)
{
    channel->fd = fd;
    channel->operation = NO_OP;
    channel->unread_data_start = 0;
    channel->unread_data_end = 0;
    if (crypto_box_beforenm(channel->key, (void*)remote_key, (void*)local_key) != 0)
    {
        opal_error("failed to create shared key during crypto channel initialization");
    }
}


void crypto_channel_fini(crypto_channel_t *channel)
{
    (void)channel;
}


int crypto_channel_write(crypto_channel_t *channel, const void *buffer, size_t bytes)
{
    if (channel == NULL)
    {
        return CHANNEL_ERROR;
    }
    // Prepare for writing
    channel->write_buffer = buffer;
    channel->write_total = bytes;
    channel->write_processed = 0;
    channel->ciphertext_processed = 0;
    channel->ciphertext_length = 0;
    channel->plaintext_length = 0;
    channel->operation = WRITE_OP;
    // Execute writing operation
    return crypto_channel_write_continue(channel);
}


int crypto_channel_read(crypto_channel_t *channel, void *buffer, size_t bytes)
{
    if (channel == NULL)
    {
        return CHANNEL_ERROR;
    }
    // Prepare for reading
    channel->read_buffer = buffer;
    channel->read_total = bytes;
    channel->read_processed = 0;
    channel->ciphertext_processed = 0;
    channel->ciphertext_length = CRYPTO_HEADER_SIZE;
    channel->plaintext_length = 0;
    channel->operation = READ_OP;
    // Execute reading operation
    return crypto_channel_read_continue(channel);
}


int crypto_channel_continue(crypto_channel_t *channel)
{
    if (channel == NULL)
    {
        return CHANNEL_ERROR;
    }
    switch (channel->operation)
    {
        case READ_OP:
            return crypto_channel_read_continue(channel);
        case WRITE_OP:
            return crypto_channel_write_continue(channel);
        case NO_OP:
            return CHANNEL_SUCCESS;
        default:
            return CHANNEL_ERROR;
    }
}
