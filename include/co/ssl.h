#pragma once
#include "co.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace co {

void ssl_init(void);

SSL_CTX *ssl_create_ctx(int protocols);
int ssl_certificate(SSL_CTX *ctx, const std::string &cert_file, const std::string &key_file);
int ssl_certificate_chain(SSL_CTX *ctx, const std::string &cert_file, const std::string &key_file);
int ssl_ctx_set_cipher_list(SSL_CTX *ctx, const char *ciphers);
int ssl_ctx_set_verify(SSL_CTX *ctx, int depth, const std::string &cli_cert_file);
int ssl_ctx_set_options(SSL_CTX *ctx, long opts);
int ssl_ctx_set_timeout(SSL_CTX *ctx, int tm);


int ssl_ctx_set_cache_mode(SSL_CTX *ctx, int mode = SSL_SESS_CACHE_SERVER);
int ssl_ctx_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid, size_t sid_len);
SSL_SESSION *ssl_get_session(SSL *ssl);
void ssl_free_session(SSL_SESSION *s);
int ssl_generate_rsa512_key(SSL_CTX *ctx, RSA *&key);


SSL *ssl_create_connection(SSL_CTX *ctx, sock_t fd, bool is_cli = false);
int ssl_do_handshake(SSL *ssl, sock_t fd);
int ssl_read(SSL *ssl, sock_t fd, void *buf, size_t size);
int ssl_write(SSL *ssl, sock_t fd, const char *buf, size_t n);
int ssl_shutdown(SSL *ssl, sock_t fd, char c);


const char *ssl_get_cipher_name(SSL *ssl);
const char *ssl_get_proto(SSL *ssl);
int ssl_get_subject_dn(SSL *ssl, std::string &subject);
int ssl_get_issuer_dn(SSL *ssl, std::string &issuer);

} // namespace co
