#include <endian.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdbool.h>
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
    // Generate a nonce
    randombytes_buf(channel->ciphertext_nonce, crypto_box_NONCEBYTES);
    // Encrypt the plaintext, storing it into channel->ciphertext_data
    crypto_box_easy_afternm(
        channel->ciphertext_data,
        channel->plaintext,
        channel->plaintext_length,
        channel->ciphertext_nonce,
        channel->shared_key
    );
    // Store the ciphertext network length
    channel->ciphertext_network_length = htobe16(channel->plaintext_length);
    // Store ciphertext size and zero processed bytes
    channel->ciphertext_length = channel->plaintext_length + (crypto_box_MACBYTES + CRYPTO_HEADER_SIZE);
    channel->ciphertext_processed = 0;
    #ifdef VERBOSE_DEBUG
    opal_debug_info("Encrypted to ciphertext (%02x%02x...%02x%02x) using nonce (%02x%02x...%02x%02x)",
            channel->ciphertext_data[0],
            channel->ciphertext_data[1],
            channel->ciphertext_data[channel->ciphertext_length - CRYPTO_HEADER_SIZE - 2],
            channel->ciphertext_data[channel->ciphertext_length - CRYPTO_HEADER_SIZE - 1],
            channel->ciphertext_nonce[0],
            channel->ciphertext_nonce[1],
            channel->ciphertext_nonce[crypto_box_NONCEBYTES - 2],
            channel->ciphertext_nonce[crypto_box_NONCEBYTES - 1]);
    #endif
}


static int crypto_channel_decrypt_chunk(crypto_channel_t *channel)
{
    #ifdef VERBOSE_DEBUG
    opal_debug_info("Decrypting ciphertext (%02x%02x...%02x%02x) using nonce (%02x%02x...%02x%02x)",
            channel->ciphertext_data[0],
            channel->ciphertext_data[1],
            channel->ciphertext_data[channel->ciphertext_length - CRYPTO_HEADER_SIZE - 2],
            channel->ciphertext_data[channel->ciphertext_length - CRYPTO_HEADER_SIZE - 1],
            channel->ciphertext_nonce[0],
            channel->ciphertext_nonce[1],
            channel->ciphertext_nonce[crypto_box_NONCEBYTES - 2],
            channel->ciphertext_nonce[crypto_box_NONCEBYTES - 1]);
    #endif
    // Perform decryption, putting data into channel->plaintext
    int status = crypto_box_open_easy_afternm(
        channel->plaintext,
        channel->ciphertext_data,
        channel->ciphertext_length - CRYPTO_HEADER_SIZE,
        channel->ciphertext_nonce,
        channel->shared_key
    );
    // Store plaintext size
    channel->plaintext_length = channel->ciphertext_length - (CRYPTO_HEADER_SIZE + crypto_box_MACBYTES);
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
                channel->ciphertext_length = be16toh(channel->ciphertext_network_length) + CRYPTO_HEADER_SIZE + crypto_box_MACBYTES;
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
        if (channel->write_processed == channel->write_total)
        {
            break;
        }

        // Determine a size for the next chunk
        channel->plaintext_length = MIN(channel->write_total - channel->write_processed, CRYPTO_PACKET_MAX);
        // Move the chunk into the plaintext buffer
        memcpy(channel->plaintext, channel->write_buffer + channel->write_processed, channel->plaintext_length);
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
            opal_debug_error("decryption failed on incoming message");
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


static int crypto_channel_connect_read_continue(crypto_channel_t *channel)
{
    // Read the incoming public key until complete
    while (channel->read_processed < sizeof(public_key_t))
    {
        ssize_t bytes_read = read(
                channel->fd,
                channel->temporary_public_key_buffer + channel->read_processed,
                sizeof(public_key_t) - channel->read_processed);
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
            channel->read_processed += bytes_read;
        }
    }

    // If key compare is on, make sure these keys match
    if (channel->key_compare)
    {
        if (sodium_memcmp(
            channel->remote_public_key,
            channel->temporary_public_key_buffer,
            sizeof(public_key_t)) != 0)
        {
            opal_error("could not validate remote public key");
            return CHANNEL_ERROR;
        }
    }
    // If key compare is off, use this key as the remote public key
    else
    {
        memcpy(channel->remote_public_key,
            channel->temporary_public_key_buffer,
            sizeof(public_key_t));
    }

    // Derive a shared key
    if (crypto_box_beforenm(channel->shared_key,
        channel->remote_public_key,
        channel->private_key) != 0)
    {
        opal_error("failed to generate shared key");
        return CHANNEL_ERROR;
    }

    return CHANNEL_SUCCESS;
}


static int crypto_channel_connect_write_continue(crypto_channel_t *channel)
{
    while (channel->write_processed < sizeof(public_key_t))
    {
        ssize_t bytes_written = write(
                channel->fd,
                channel->local_public_key + channel->write_processed,
                sizeof(public_key_t) - channel->write_processed);
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
            channel->write_processed += bytes_written;
        }
    }

    channel->operation = CONNECT_READ_OP;
    channel->read_processed = 0;
    return crypto_channel_connect_read_continue(channel);
}


// Public functions
void crypto_generate_keys(void *public_key, void *private_key)
{
    crypto_box_keypair(public_key, private_key);
}


void crypto_generate_public_key(void *public_key, const void *private_key)
{
    crypto_scalarmult_base(public_key, private_key);
}


crypto_channel_t *crypto_channel_new(int fd, const void *private_key, const void *public_key)
{
    crypto_channel_t *channel = malloc(sizeof(crypto_channel_t));
    if (channel == NULL)
    {
        return NULL;
    }
    crypto_channel_init(channel, fd, private_key, public_key);
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


void crypto_channel_init(crypto_channel_t *channel, int fd, const void *private_key, const void *public_key)
{
    channel->fd = fd;
    channel->operation = NO_OP;
    channel->unread_data_start = 0;
    channel->unread_data_end = 0;
    if (private_key == NULL)
    {
        crypto_generate_keys(channel->local_public_key, channel->private_key);
    }
    else if (public_key == NULL)
    {
        memcpy(channel->private_key, private_key, sizeof(private_key_t));
        crypto_generate_public_key(channel->local_public_key, private_key);
    }
    else
    {
        memcpy(channel->private_key, private_key, sizeof(private_key_t));
        memcpy(channel->local_public_key, public_key, sizeof(public_key_t));
    }
}


int crypto_channel_connect(crypto_channel_t *channel, const void *remote_public_key)
{
    if (channel == NULL)
    {
        return CHANNEL_ERROR;
    }
    if (remote_public_key == NULL)
    {
        channel->key_compare = false;
    }
    else
    {
        memcpy(channel->remote_public_key, remote_public_key, sizeof(public_key_t));
        channel->key_compare = true;
    }
    channel->operation = CONNECT_WRITE_OP;
    channel->write_processed = 0;
    return crypto_channel_connect_write_continue(channel);
}


void crypto_channel_fini(crypto_channel_t *channel)
{
    sodium_memzero(channel->shared_key, crypto_box_BEFORENMBYTES);
    sodium_memzero(channel->private_key, crypto_box_SECRETKEYBYTES);
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
        case CONNECT_READ_OP:
            return crypto_channel_connect_read_continue(channel);
        case CONNECT_WRITE_OP:
            return crypto_channel_connect_write_continue(channel);
        case NO_OP:
            return CHANNEL_SUCCESS;
        default:
            return CHANNEL_ERROR;
    }
}
