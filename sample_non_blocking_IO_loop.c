// Data_transfer takes two SSL objects as params, which are expected to have
// connection to two different peers.
// Data_transfer will read data from A and write it to B, and at the same time
// read data from B and write it to A.

// Three functions that are not explicitly defined:
// 1. set_nonblocking(SSL *) must be implemented in a platform-specific way to
//    set the underlying I/O layer of the SSL object to be non-blocking.
// 2. set_blocking(SSL *) sets the connection to a blocking state.
// 3. check_availability() checks the I/O status of the underlying layers of
//    both A and B and set the variables appropriately.
//    This function should wait until at least one variable is set before
//    returning.
//    We CANNOT perform any I/O operations if nothing is available for either
//    connection.
// On a Unix system with SSL objects based on sockets, set_nonblocking and
// set_blocking can be implemented using the fcntl system call, and the
// check_availability function can use fd_set data structures along with the
// select system call.

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

#define BUF_SIZE 80

void data_transfer(SSL * A, SSL * B) {
    // the buffers and the size variables
    unsigned char A2B[BUF_SIZE];
    unsigned char B2A[BUF_SIZE];
    // hold the number of bytes of data in their counterpart buffer
    unsigned int A2B_len = 0;
    unsigned int B2A_len = 0;
    // flags to mark that we have some data to write,
    // i.e., whether there is any data in our buffers.
    // We could leave these two vars out, since throughout the function
    // they will be 0 only if the corresponding buffer length's var is also 0.
    // We opted to use them for code readability.
    unsigned int have_data_A2B = 0;
    unsigned int have_data_B2A = 0;
    // flags set by check_availability() that poll for I/O status,
    // i.e., the connection is available to perform the operation without
    // needing to block.
    unsigned int can_read_A = 0;
    unsigned int can_read_B = 0;
    unsigned int can_write_A = 0;
    unsigned int can_write_B = 0;
    // flags to mark all the combinations of why we're blocking
    // The flag tells us that a particular kind of I/O operation requires the
    // availability of the connection to perform another kind of I/O operation.
    // If write_waiton_read_B is set, it means that the last write operation
    // performed on B must be retried after B is available to read.
    unsigned int read_waiton_write_A = 0;
    unsigned int read_waiton_write_B = 0;
    unsigned int read_waiton_read_A = 0;
    unsigned int read_waiton_read_B = 0;
    unsigned int write_waiton_write_A = 0;
    unsigned int write_waiton_write_B = 0;
    unsigned int write_waiton_read_A = 0;
    unsigned int write_waiton_read_B = 0;
    // variable to hold return value of an I/O operation
    int code;

    // make the underlying I/O layer behind each SSL object non-blocking
    set_nonblocking(A);
    set_nonblocking(B);
    // SSL_MODE_ENABLE_PARTIAL_WRITE instructs the library to allow partially
    // write operations successfully (SSL_write return success).
    SSL_set_mode(A, SSL_MODE_ENABLE_PARTIAL_WRITE|
                    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_mode(B, SSL_MODE_ENABLE_PARTIAL_WRITE|
                    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    while (1) {
        // check I/O availability and set flags
        check_availability(A, &can_read_A, &can_write_A,
                           B, &can_read_B, &can_write_B);

        // this "if" statement reads data from A. it will only be entered if
        // the following conditions are all true:
        // 1. we're not in the middle of a write on A
        // 2. there's space left in the A to B buffer
        // 3. either we need to write to complete a previously blocked read
        //    and now A is abailable to write, or we can read from A regardless
        //    of whether we're blocking for availability to read.
        if (!(write_waiton_read_A || write_waiton_write_A) &&
            (A2B_len != BUF_SIZE) &&
            (can_read_A || (can_write_A && read_waiton_write_A))) {
            // clear the flags since we'll set them based on the I/O call's return
            read_waiton_read_A = 0;
            read_waiton_write_A = 0;

            // read into the buffer after the current position
            code = SSL_read(A, A2B + A2B_len, BUF_SIZE - A2B_len);
            switch (SSL_get_error(A, code)) {
            case SSL_ERROR_NONE:
                // no errors occurred. update the new length and make sure the
                // "have data" flag is set.
                A2B_len += code;
                have_data_A2B = 1;
                break;
            case SSL_ERROR_ZERO_RETURN:
                // connection closed.
                goto end;
            case SSL_ERROR_WANT_READ:
                // we need to retry the read after A is available for reading.
                read_waiton_read_A = 1;
                break;
            case SSL_ERROR_WANT_WRITE:
                // we need to retry the read after A is available for writing.
                read_waiton_writen_A = 1;
                break;
            default:
                // ERROR
                goto err;
            }
        }

        // this "if" statement is roughly the same as the previous "if" statement
        // with A and B switched
        if (!(write_waiton_read_B || write_waiton_write_B) &&
            (B2A_len != BUF_SIZE) &&
            (can_read_B || (can_write_B && read_waiton_write_B))) {
            read_waiton_read_B = 0;
            read_waiton_write_B = 0;
            
            code = SSL_read(B, B2A + B2A_len, BUF_SIZE - B2A_len);
            switch (SSL_get_error(B, code))
            {
                case SSL_ERROR_NONE:
                    B2A_len += code;
                    have_data_B2A = 1;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    goto end;
                case SSL_ERROR_WANT_READ:
                    read_waiton_read_B = 1;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    read_waiton_write_B = 1;
                    break;
                default:
                    goto err;
            }
        }
               /* this "if" statement writes data to A. it will only be entered if
         * the following conditions are all true:
         * 1. we're not in the middle of a read on A
         * 2. there's data in the A to B buffer
         * 3. either we need to read to complete a previously blocked write
         *    and now A is available to read, or we can write to A
         *    regardless of whether we're blocking for availability to write
         */
        if (!(read_waiton_write_A || read_waiton_read_A) &&
            have_data_B2A &&
            (can_write_A || (can_read_A && write_waiton_read_A)))
        {
            /* clear the flags */
            write_waiton_read_A = 0;
            write_waiton_write_A = 0;
 
            /* perform the write from the start of the buffer */
            code = SSL_write(A, B2A, B2A_len);
            switch (SSL_get_error(A, code))
            {
                case SSL_ERROR_NONE:
                    /* no error occured. adjust the length of the B to A
                     * buffer to be smaller by the number bytes written.  If
                     * the buffer is empty, set the "have data" flags to 0,
                     * or else, move the data from the middle of the buffer
                     * to the front.
                     */
                    B2A_len -= code;
                    if (!B2A_len)
                        have_data_B2A = 0;
                    else
                        memmove(B2A, B2A + code, B2A_len);
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    /* connection closed */
                    goto end;
                case SSL_ERROR_WANT_READ:
                    /* we need to retry the write after A is available for
                     * reading
                     */
                    write_waiton_read_A = 1;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    /* we need to retry the write after A is available for
                     * writing
                     */
                    write_waiton_write_A = 1;
                    break;
                default:
                    /* ERROR */
                    goto err;
            }
        }
 
        /* this "if" statement is roughly the same as the previous "if"
         * statement with A and B switched
         */
        if (!(read_waiton_write_B || read_waiton_read_B) &&
            have_data_A2B &&
            (can_write_B || (can_read_B && write_waiton_read_B)))
        {
            write_waiton_read_B = 0;
            write_waiton_write_B = 0;
 
            code = SSL_write(B, A2B, A2B_len);
            switch (SSL_get_error(B, code))
            {
                case SSL_ERROR_NONE:
                    A2B_len -= code;
                    if (!A2B_len)
                        have_data_A2B = 0;
                    else
                        memmove(A2B, A2B + code, A2B_len);
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    /* connection closed */
                    goto end;
                case SSL_ERROR_WANT_READ:
                    write_waiton_read_B = 1;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    write_waiton_write_B = 1;
                   break;
                default:
                    /* ERROR */
                    goto err;
            }
        }
    }
 
err:
    /* if we errored, print then before exiting */
    fprintf(stderr, "Error(s) occured\n");
    ERR_print_errors_fp(stderr);
end:
    /* close down the connections. set them back to blocking to simplify. */
    set_blocking(A);
    set_blocking(B);
    SSL_shutdown(A);
    SSL_shutdown(B);
}
