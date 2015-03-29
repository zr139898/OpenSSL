// code fragment to force a renegotiation from a server


// assume ssl is connected and error free up to here
// ensure the SSL object is blocking so we don't need to retry failed I/O calls.
set_blocking(ssl);              // this is unnecessary if it's already blocking
SSL_renegotiate(ssl);           // sends out the request to the peer.
// SSL_do_handshake is a generic routine that calls the accept function for
// server objects or the connect function for the client objects.
// This first call to SSL_do_handshake sends out request and returns.
SSL_do_handshake(ssl);
// check that the SSL connection hasn't received any errors. do this by making
// sure its state is SSL_ST_OK.
if (ssl->state != SSL_ST_OK)
    int_error("Failed to send renegotiation request");
// At this point, if we call the handshake function again, it will just return
// if the peer chose not to renegotiate.
// Since we have a reason for renegotiating, and we need it to complete before
// continuing, we must manually set the SSL_ST_ACCEPT state of the server object,
// which will cause the subsequent call to SSL_do_handshake, which will force
// a handshake to occur before continuing.
ssl->state |= SSL_ST_ACCEPT;
SSL_do_handshake(ssl);
if (ssl->state != SSL_ST_OK)
    int_error("Failed to complete renegotiation");
// our renegotiation is complete

////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// This fragment is for a caching server that wishes to upgrade client
// authentication; if our server isn't caching, we can omit the calls to set the
// session ID context.
// Code to cause forced renegotiation in order to request stronger client
// authentication and distinguish the sessions.

// assume ctx is an SSL_CTX object that is setup to not have any verify options.
int normal_user = 1;
int admin_user = 2;
SSL_CTX_set_session_id_context(ctx, &normal_user, sizeof(int));
// perform rest of the ctx setup, create an ssl object, and connect it.
// normal SSL I/O operations and application code go here.
// if we want to upgrade client previlege, we enter the following code block.
SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
               verify_callback);
SSL_set_session_id_context(ssl, &admin_user, sizeof(int));
// code fragment from above goes here. the new session is made
post_connection_check(ssl, host);
// if everything is error-free, we have properly authenticated the client.


////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
// passive renegotiation in Version 0.9.7

