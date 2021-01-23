#include <iostream>
#include <memory>
#include <sstream>
#include <thread>

#include "co/co.h"
#include "co/log.h"
#include "co/os.h"
#include "co/so/tcp.h"
#include "co/time.h"

#ifdef COSSL
#include "co/ssl.h"

static std::string &&ssl_error_str() { return std::string(ERR_reason_error_string(ERR_get_error())); }

thread_local SSL_CTX* thread_ssl_ctx = nullptr;

SSL_CTX *get_ssl_ctx(void) {
  if (!thread_ssl_ctx) {
    SSL_CTX *ctx = co::ssl_create_ctx(0);
    if (!ctx) {
      CLOG << "ssl_create_ctx failed";
      return nullptr;
    }

    // 要求校验对方证书
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // 加载CA的证书
    //! SSL_CTX_load_verify_locations(ctx, "cacert.cer", NULL);

    // 加载自己的证书 && 私钥
    int r = co::ssl_certificate_chain(ctx, "server.pem", "server.pem");
    if (r < 0) {
      CLOG << "ssl_certificate failed";
      // CLOG << "SSL_CTX_use_certificate_file failed";
      return nullptr;
    }

    // 判定私钥是否正确
    r = SSL_CTX_check_private_key(ctx);
    if (!r) {
      CLOG << "SSL_CTX_check_private_key failed";
      return nullptr;
    }

    thread_ssl_ctx = ctx;
  }

  return thread_ssl_ctx;
}

class TestServer : public tcp::Server {
public:
  TestServer(const char *ip, int port) : tcp::Server(ip, port) {}
  ~TestServer() = default;

  void on_connection(tcp::Connection *conn) override {
    int fd = conn->fd;
    CLOG << "on_connection " << conn->ip << ":" << conn->port << ", fd=" << fd;

    SSL *ssl = co::ssl_create_connection(get_ssl_ctx(), fd);
    if (!ssl) {
      CLOG << "ssl_create_connection failed";
      close(fd);
      return;
    }

    auto ret = co::ssl_do_handshake(ssl, fd);
    if (ret != 1) {
      CLOG << "SSL_do_handshake fail: ret=" << ret << ", err=" << ERR_get_error();
      co::ssl_shutdown(ssl, fd, 'a');
      close(fd);
      return;
    }

    char buf[1024]{};
    ret = co::ssl_read(ssl, fd, buf, sizeof(buf));
    if (ret <= 0) {
      CLOG << "SSL_read fail: " << ssl_error_str();
      co::ssl_shutdown(ssl, fd, 'a');
      close(fd);
      return;
    }
    CLOG << "SSL_read " << strlen(buf) << " : " << std::string(buf);

    const char *resp = "HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
    ret = co::ssl_write(ssl, fd, resp, strlen(resp));
    CLOG << "ssl_write " << ret;

    co::ssl_shutdown(ssl, fd, 'a');
    close(fd);
  }
};
#endif // COSSL

int main(int argc, char **argv) {
  flag::init(argc, argv);
  log::init();

#ifdef COSSL
  co::ssl_init();

  auto ctx = get_ssl_ctx();
  assert(ctx);

  auto srv = new TestServer("127.0.0.1", 40000);
  srv->start();

  sleep::ms(100000000);
#else
  FLOG << "You Should Enable COSSL at xmake.lua";
#endif
}