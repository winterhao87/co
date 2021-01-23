#ifndef COSSL
#pragma message("COSSL UnDefined")
#else
#include "hook.h"
#include "io_event.h"
#include "scheduler.h"
#include "co/ssl.h"

namespace co {

static long ssl_protocols[] = {
    SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1,
    SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3,
    SSL_OP_NO_SSLv3,
    SSL_OP_NO_SSLv2,
    0,
};

void ssl_init(void) {
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
}

SSL_CTX *ssl_create_ctx(int protocols) {
  SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
  if (!ctx) return nullptr;

  /* client side options */

  SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);

  /* server side options */

  SSL_CTX_set_options(ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

  /* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
  SSL_CTX_set_options(ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);

  SSL_CTX_set_options(ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_TLS_D5_BUG);
  SSL_CTX_set_options(ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
  SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

  if (ssl_protocols[protocols >> 1] != 0) {
    SSL_CTX_set_options(ctx, ssl_protocols[protocols >> 1]);
  }

  SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  SSL_CTX_set_read_ahead(ctx, 1);

  return ctx;
}

int ssl_certificate(SSL_CTX *ctx, const std::string &cert_file, const std::string &key_file) {
  if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
    WLOG << "SSL_CTX_use_certificate_file(" << cert_file << ") fail";
    return -1;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) == 0) {
    WLOG << "SSL_CTX_use_PrivateKey_file(" << key_file << ") fail";
    return -2;
  }

  return 0;
}

int ssl_certificate_chain(SSL_CTX *ctx, const std::string &cert_file, const std::string &key_file) {
  if (SSL_CTX_use_certificate_chain_file(ctx, cert_file.c_str()) == 0) {
    WLOG << "SSL_CTX_use_certificate_chain_file(" << cert_file << ") fail";
    return -1;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) == 0) {
    WLOG << "SSL_CTX_use_PrivateKey_file(" << key_file << ") fail";
    return -2;
  }

  return 0;
}

int ssl_ctx_set_cipher_list(SSL_CTX *ctx, const char *ciphers) {
  if (ssl_ctx_set_cipher_list(ctx, ciphers) == 0) {
    return -1;
  }

  return 0;
}

int ssl_ctx_set_verify(SSL_CTX *ctx, int depth, const std::string &cli_cert_file) {
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(ctx, depth);
  if (cli_cert_file.size()) {
    if (SSL_CTX_load_verify_locations(ctx, cli_cert_file.c_str(), NULL) == 0) {
      return -1;
    }
  }

  return 0;
}

int ssl_ctx_set_options(SSL_CTX *ctx, long opts) { return SSL_CTX_set_options(ctx, opts); }

int ssl_ctx_set_cache_mode(SSL_CTX *ctx, int mode) { return SSL_CTX_set_session_cache_mode(ctx, mode); }

int ssl_ctx_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid, size_t sid_len) {
  return SSL_CTX_set_session_id_context(ctx, sid, sid_len);
}

int ssl_ctx_set_timeout(SSL_CTX *ctx, int tm) { return SSL_CTX_set_timeout(ctx, tm); }

SSL_SESSION *ssl_get_session(SSL *ssl) { return SSL_get1_session(ssl); }
void ssl_free_session(SSL_SESSION *s) { SSL_SESSION_free(s); }

int ssl_generate_rsa512_key(SSL_CTX *ctx, RSA *&key) {
  if (SSL_CTX_need_tmp_RSA(ctx) == 0) return 0;

  key = RSA_generate_key(512, RSA_F4, NULL, NULL);
  if (!key) return -1;

  SSL_CTX_set_tmp_rsa(ctx, key);
  return 0;
}

SSL *ssl_create_connection(SSL_CTX *ctx, sock_t fd, bool is_cli) {
  SSL *ssl = SSL_new(ctx);
  if (!ssl) return ssl;

  if (SSL_set_fd(ssl, fd) == 0) {
    SSL_free(ssl);
    return nullptr;
  }

  if (is_cli) {
    SSL_set_connect_state(ssl);
  } else {
    SSL_set_accept_state(ssl);
  }

  return ssl;
}

int ssl_do_handshake(SSL *ssl, sock_t fd) {
  CHECK(gSched) << "must be called in coroutine..";
  IoEvent ev_r(fd, EV_read);
  IoEvent ev_w(fd, EV_write);

  do {
    int ret = SSL_do_handshake(ssl);
    if (ret == 1) return 1;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_WRITE) {
      ev_w.wait();
    } else if (err == SSL_ERROR_WANT_READ) {
      ev_r.wait();
    } else {
      return -err;
    }

  } while (true);
}

int ssl_read(SSL *ssl, sock_t fd, void *buf, size_t size) {
  CHECK(gSched) << "must be called in coroutine..";
  IoEvent ev_r(fd, EV_read);

  do {
    int ret = SSL_read(ssl, buf, size);
    if (ret >= 0) return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
      ev_r.wait();
    } else {
      return -err;
    }

  } while (true);
}

int ssl_write(SSL *ssl, sock_t fd, const char *buf, size_t n) {
  CHECK(gSched) << "must be called in coroutine..";
  if (n == 0) return 0;

  IoEvent ev_w(fd, EV_write);

  do {
    int ret = SSL_write(ssl, buf, n);
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_WRITE) {
      ev_w.wait();
    } else {
      return -err;
    }

  } while (true);
}

int ssl_shutdown(SSL *ssl, sock_t fd, char c) {
  CHECK(gSched) << "must be called in coroutine..";
  int mode;

  if (c == 'r') {
    mode |= SSL_RECEIVED_SHUTDOWN;
  } else if (c == 'w') {
    mode |= SSL_SENT_SHUTDOWN;
  } else {
    mode = SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN;
  }

  int old = SSL_get_shutdown(ssl);
  mode |= old;

  SSL_set_shutdown(ssl, mode);

  IoEvent ev_r(fd, EV_read);
  IoEvent ev_w(fd, EV_write);
  do {
    int ret = SSL_shutdown(ssl);
    if (ret == 1) {
      SSL_free(ssl);
      return ret;
    }

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
      ev_r.wait();
    } else if (err == SSL_ERROR_WANT_WRITE) {
      ev_w.wait();
    } else {
      SSL_free(ssl);
      return -err;
    }
  } while (true);
}

const char *ssl_get_cipher_name(SSL *ssl) { return SSL_get_cipher_name(ssl); }

const char *ssl_get_proto(SSL *ssl) { return SSL_get_version(ssl); }

int ssl_get_subject_dn(SSL *ssl, std::string &subject) {
  X509 *cert = SSL_get_peer_certificate(ssl);
  if (!cert) return 0;

  X509_NAME *name = X509_get_subject_name(cert);
  if (!name) return -1;

  char *p = X509_NAME_oneline(name, NULL, 0);
  if (!p) return -2;

  subject.assign(p);
  OPENSSL_free(p);
  return 0;
}

int ssl_get_issuer_dn(SSL *ssl, std::string &issuer) {
  X509 *cert = SSL_get_peer_certificate(ssl);
  if (!cert) return 0;

  X509_NAME *name = X509_get_issuer_name(cert);
  if (!name) return -1;

  char *p = X509_NAME_oneline(name, NULL, 0);
  if (!p) return -2;

  issuer.assign(p);
  OPENSSL_free(p);
  return 0;

}

} // namespace co

#endif // COSSL