// BIO_chain.c -- assembling and using a BIO chain

int  write_data(const char * filename, char * out, int len, unsigned char * key) {
    int total, written;
    BIO * cipher, * b64, * buffer, * file;

    // Create a buffered file BIO for writing
    file = BIO_new_file(filename, "w");
    if (!file) return 0;

    // create a buffering filter BIO to buffer writes to the file
    buffer = BIO_new(BIO_f_buffer());

    // create a base64 encoding filter BIO
    b64 = BIO_new(BIO_f_base64());

    // create the cipher filter BIO and set the key.
    // The last param of BIO_set_cipher is 1 for encryption and 0 for decryption
    cipher = BIO_new(BIO_f_cipher());
    BIO_set_cipher(cipher, EVP_des_ede3_cbc(), key, NULL, 1);

    // assemble the BIO chain to be in the order cipher-b64-buffer-file
    BIO_push(cipher, b64);
    BIO_push(b64, buffer);
    BIO_push(buffer, file);

    // This loop writes the data to the file.
    // It checks for errors as if the underlying file were non-blocking
    for (total = 0; total < len; total += written) {
        if ((written = BIO_written(cipher, out + total, len - total)) <= 0) {
            if (BIO_should_retry(cipher)) {
                written = 0;
                continue;
            }
            break;
        }
    }

    // ensure all of our data is pushed all the way to the file
    BIO_flush(cipher);

    // we now need to free the BIO chain.
    // A call to BIO_free_all(cipher) would accomplish this,
    // but we'll first remove b64 from the chain for demonstration purposes.
    BIO_pop(b64);

    // at this point, the b64 BIO is isolated and the chain is cipher-buffer-file.
    // The following frees all of that memory.
    BIO_free(b64);
    BIO_free_all(cipher);
}