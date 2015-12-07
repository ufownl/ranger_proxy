// ranger_proxy - A SOCKS5 proxy
// Copyright (C) 2015  RangerUFO <ufownl@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "test_util.hpp"
#include "socks5_service.cpp"
#include "socks5_session.cpp"
#include "gate_service.cpp"
#include "gate_session.cpp"
#include "deadline_timer.cpp"
#include "user_table.cpp"
#include "aes_cfb128_encryptor.cpp"
#include "zlib_encryptor.cpp"
#include "logger_ostream.cpp"
#include "logger.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <string.h>

TEST_F(echo_test, socks5_no_auth_conn_ipv4) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x00};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(sizeof(sin.sin_addr), send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0));
    uint16_t remote_port = htons(m_port);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  {
    // test data
    char buf[] = "Hello, world!";
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    memset(buf, 0, sizeof(buf));
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("Hello, world!", buf);
  }
}

TEST_F(echo_test, socks5_no_auth_conn_domainname) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x00};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x03};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    char ip[] = "127.0.0.1";
    uint8_t len = sizeof(ip) - 1;
    ASSERT_EQ(sizeof(len), send(fd, &len, sizeof(len), 0));
    ASSERT_EQ(len, send(fd, ip, len, 0));
    uint16_t remote_port = htons(m_port);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  {
    // test data
    char buf[] = "Hello, world!";
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("Hello, world!", buf);
  }
}

TEST_F(ranger_proxy_test, socks5_no_auth_conn_ipv4_null) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  for (auto i = 0; i < 10; ++i) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(-1, fd);
    scope_guard guard_fd([fd] { close(fd); });

    sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(port);
    ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

    {
      // version identifier/method selection message
      uint8_t buf[] = {0x05, 0x01, 0x00};
      ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    }

    {
      // method selection message
      uint8_t buf[2];
      ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
      ASSERT_EQ(0x05, buf[0]);
      ASSERT_EQ(0x00, buf[1]);
    }

    {
      // request
      uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
      ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
      ASSERT_EQ(sizeof(sin.sin_addr), send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0));
      uint16_t remote_port = htons(0);
      ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
    }

    {
      // reply
      uint8_t buf[4];
      ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
      ASSERT_EQ(0x05, buf[0]);
      ASSERT_EQ(0x05, buf[1]);
      ASSERT_EQ(0x00, buf[2]);
      ASSERT_EQ(0x01, buf[3]);
      uint32_t reply_addr;
      ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
      uint16_t reply_port;
      ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
    }
  }
}

TEST_F(ranger_proxy_test, socks5_no_auth_conn_domainname_null) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  for (auto i = 0; i < 10; ++i) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(-1, fd);
    scope_guard guard_fd([fd] { close(fd); });

    sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(port);
    ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

    {
      // version identifier/method selection message
      uint8_t buf[] = {0x05, 0x01, 0x00};
      ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    }

    {
      // method selection message
      uint8_t buf[2];
      ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
      ASSERT_EQ(0x05, buf[0]);
      ASSERT_EQ(0x00, buf[1]);
    }

    {
      // request
      uint8_t buf[] = {0x05, 0x01, 0x00, 0x03};
      ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
      char ip[] = "127.0.0.1";
      uint8_t len = sizeof(ip) - 1;
      ASSERT_EQ(sizeof(len), send(fd, &len, sizeof(len), 0));
      ASSERT_EQ(len, send(fd, ip, len, 0));
      uint16_t remote_port = htons(0);
      ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
    }

    {
      // reply
      uint8_t buf[4];
      ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
      ASSERT_EQ(0x05, buf[0]);
      ASSERT_EQ(0x05, buf[1]);
      ASSERT_EQ(0x00, buf[2]);
      ASSERT_EQ(0x01, buf[3]);
      uint32_t reply_addr;
      ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
      uint16_t reply_port;
      ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
    }
  }
}

TEST_F(echo_test, encrypted_socks5_no_auth_conn_ipv4) {
  std::string str = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";
  std::vector<uint8_t> key(str.begin(), str.end());

  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  auto gate = caf::io::spawn_io(ranger::proxy::gate_service_impl, 300, std::string());
  scope_guard guard_gate([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->sync_send(socks5, caf::publish_atom::value, static_cast<uint16_t>(0),
                    key, false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  {
    caf::scoped_actor self;
    self->send(gate, caf::add_atom::value, "127.0.0.1", port, key, false);
    self->sync_send(gate, caf::publish_atom::value, static_cast<uint16_t>(0)).await(
      [&port] (caf::ok_atom, uint16_t gate_port) {
        port = gate_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x00};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(sizeof(sin.sin_addr), send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0));
    uint16_t remote_port = htons(m_port);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  {
    // test data
    char buf[] = "Hello, world!";
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    memset(buf, 0, sizeof(buf));
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("Hello, world!", buf);
  }
}

TEST_F(ranger_proxy_test, encrypt_socks5_no_auth_conn_ipv4_null) {
  std::string str = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";
  std::vector<uint8_t> key(str.begin(), str.end());

  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  auto gate = caf::io::spawn_io(ranger::proxy::gate_service_impl, 300, std::string());
  scope_guard guard_gate([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->sync_send(socks5, caf::publish_atom::value, static_cast<uint16_t>(0),
                    key, false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  {
    caf::scoped_actor self;
    self->send(gate, caf::add_atom::value, "127.0.0.1", port, key, false);
    self->sync_send(gate, caf::publish_atom::value, static_cast<uint16_t>(0)).await(
      [&port] (caf::ok_atom, uint16_t gate_port) {
        port = gate_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x00};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(sizeof(sin.sin_addr), send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0));
    uint16_t remote_port = htons(0);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x05, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  while (caf::detail::singletons::get_actor_registry()->running() > 2) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

TEST_F(ranger_proxy_test, encrypt_socks5_no_auth_conn_domainname_null) {
  std::string str = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";
  std::vector<uint8_t> key(str.begin(), str.end());

  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  auto gate = caf::io::spawn_io(ranger::proxy::gate_service_impl, 300, std::string());
  scope_guard guard_gate([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->sync_send(socks5, caf::publish_atom::value, static_cast<uint16_t>(0),
                    key, false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  {
    caf::scoped_actor self;
    self->send(gate, caf::add_atom::value, "127.0.0.1", port, key, false);
    self->sync_send(gate, caf::publish_atom::value, static_cast<uint16_t>(0)).await(
      [&port] (caf::ok_atom, uint16_t gate_port) {
        port = gate_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x00};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x03};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    char ip[] = "127.0.0.1";
    uint8_t len = sizeof(ip) - 1;
    ASSERT_EQ(sizeof(len), send(fd, &len, sizeof(len), 0));
    ASSERT_EQ(len, send(fd, ip, len, 0));
    uint16_t remote_port = htons(0);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x05, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  while (caf::detail::singletons::get_actor_registry()->running() > 2) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

TEST_F(echo_test, socks5_username_auth_conn_ipv4) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->send(socks5, caf::add_atom::value, "test", "Hello, world!");
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x02};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x02, buf[1]);
  }

  {
    // username/password auth
    uint8_t ver = 0x01;
    char username[] = "test";
    uint8_t uname_len = strlen(username);
    char password[] = "Hello, world!";
    uint8_t passwd_len = strlen(password);
    ASSERT_EQ(sizeof(ver), send(fd, &ver, sizeof(ver), 0));
    ASSERT_EQ(sizeof(uname_len), send(fd, &uname_len, sizeof(uname_len), 0));
    ASSERT_EQ(uname_len, send(fd, username, uname_len, 0));
    ASSERT_EQ(sizeof(passwd_len), send(fd, &passwd_len, sizeof(passwd_len), 0));
    ASSERT_EQ(passwd_len, send(fd, password, passwd_len, 0));
  }

  {
    // auth result
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x01, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(sizeof(sin.sin_addr), send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0));
    uint16_t remote_port = htons(m_port);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  {
    // test data
    char buf[] = "Hello, world!";
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    memset(buf, 0, sizeof(buf));
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("Hello, world!", buf);
  }
}

TEST_F(echo_test, socks5_username_auth_empty_passwd_conn_ipv4) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->send(socks5, caf::add_atom::value, "test", std::string());
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x02};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x02, buf[1]);
  }

  {
    // username/password auth
    uint8_t ver = 0x01;
    char username[] = "test";
    uint8_t uname_len = strlen(username);
    uint8_t passwd_len = 0;
    ASSERT_EQ(sizeof(ver), send(fd, &ver, sizeof(ver), 0));
    ASSERT_EQ(sizeof(uname_len), send(fd, &uname_len, sizeof(uname_len), 0));
    ASSERT_EQ(uname_len, send(fd, username, uname_len, 0));
    ASSERT_EQ(sizeof(passwd_len), send(fd, &passwd_len, sizeof(passwd_len), 0));
  }

  {
    // auth result
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x01, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(sizeof(sin.sin_addr), send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0));
    uint16_t remote_port = htons(m_port);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  {
    // test data
    char buf[] = "Hello, world!";
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    memset(buf, 0, sizeof(buf));
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("Hello, world!", buf);
  }
}

TEST_F(echo_test, socks5_username_auth_conn_domainname) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->send(socks5, caf::add_atom::value, "test", "Hello, world!");
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x02};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x02, buf[1]);
  }

  {
    // username/password auth
    uint8_t ver = 0x01;
    char username[] = "test";
    uint8_t uname_len = strlen(username);
    char password[] = "Hello, world!";
    uint8_t passwd_len = strlen(password);
    ASSERT_EQ(sizeof(ver), send(fd, &ver, sizeof(ver), 0));
    ASSERT_EQ(sizeof(uname_len), send(fd, &uname_len, sizeof(uname_len), 0));
    ASSERT_EQ(uname_len, send(fd, username, uname_len, 0));
    ASSERT_EQ(sizeof(passwd_len), send(fd, &passwd_len, sizeof(passwd_len), 0));
    ASSERT_EQ(passwd_len, send(fd, password, passwd_len, 0));
  }

  {
    // auth result
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x01, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
  }

  {
    // request
    uint8_t buf[] = {0x05, 0x01, 0x00, 0x03};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    char ip[] = "127.0.0.1";
    uint8_t len = sizeof(ip) - 1;
    ASSERT_EQ(sizeof(len), send(fd, &len, sizeof(len), 0));
    ASSERT_EQ(len, send(fd, ip, len, 0));
    uint16_t remote_port = htons(m_port);
    ASSERT_EQ(sizeof(remote_port), send(fd, &remote_port, sizeof(remote_port), 0));
  }

  {
    // reply
    uint8_t buf[4];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x00, buf[1]);
    ASSERT_EQ(0x00, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    uint32_t reply_addr;
    ASSERT_EQ(sizeof(reply_addr), recv(fd, &reply_addr, sizeof(reply_addr), 0));
    uint16_t reply_port;
    ASSERT_EQ(sizeof(reply_port), recv(fd, &reply_port, sizeof(reply_port), 0));
  }

  {
    // test data
    char buf[] = "Hello, world!";
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("Hello, world!", buf);
  }
}

TEST_F(ranger_proxy_test, socks5_username_auth_failed) {
  auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl, 300, false, std::string());
  scope_guard guard_socks5([socks5] {
    caf::anon_send_exit(socks5, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    caf::scoped_actor self;
    self->send(socks5, caf::add_atom::value, "auth_failed", "auth_failed");
    self->sync_send(socks5, caf::publish_atom::value, port,
                    std::vector<uint8_t>(), false).await(
      [&port] (caf::ok_atom, uint16_t socks5_port) {
        port = socks5_port;
      },
      [] (caf::error_atom, const std::string& what) {
        std::cout << "ERROR: " << what << std::endl;
      }
    );
  }
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  scope_guard guard_fd([fd] { close(fd); });

  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

  {
    // version identifier/method selection message
    uint8_t buf[] = {0x05, 0x01, 0x02};
    ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  }

  {
    // method selection message
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x05, buf[0]);
    ASSERT_EQ(0x02, buf[1]);
  }

  {
    // username/password auth
    uint8_t ver = 0x01;
    char username[] = "test";
    uint8_t uname_len = strlen(username);
    char password[] = "Hello, world!";
    uint8_t passwd_len = strlen(password);
    ASSERT_EQ(sizeof(ver), send(fd, &ver, sizeof(ver), 0));
    ASSERT_EQ(sizeof(uname_len), send(fd, &uname_len, sizeof(uname_len), 0));
    ASSERT_EQ(uname_len, send(fd, username, uname_len, 0));
    ASSERT_EQ(sizeof(passwd_len), send(fd, &passwd_len, sizeof(passwd_len), 0));
    ASSERT_EQ(passwd_len, send(fd, password, passwd_len, 0));
  }

  {
    // auth result
    uint8_t buf[2];
    ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
    ASSERT_EQ(0x01, buf[0]);
    ASSERT_NE(0x00, buf[1]);
  }

  while (caf::detail::singletons::get_actor_registry()->running() > 2) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
