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
#include "gate_service.cpp"
#include "gate_session.cpp"
#include "deadline_timer.cpp"
#include "aes_cfb128_encryptor.cpp"
#include "zlib_encryptor.cpp"
#include "logger_ostream.cpp"
#include "logger.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

TEST_F(echo_test, gate_echo) {
  auto gate = caf::io::spawn_io(ranger::proxy::gate_service_impl, 300, std::string());
  scope_guard guard_gate([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    std::vector<uint8_t> key;
    caf::scoped_actor self;
    self->send(gate, caf::add_atom::value, "127.0.0.1", m_port, key, false);
    self->sync_send(gate, caf::publish_atom::value, port).await(
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

  char buf[] = "Hello, world!";
  ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  memset(buf, 0, sizeof(buf));
  ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
  EXPECT_STREQ("Hello, world!", buf);
}

TEST_F(echo_test, gate_chain_echo) {
  auto gate = caf::io::spawn_io(ranger::proxy::gate_service_impl, 300, std::string());
  scope_guard guard_gate([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    std::vector<uint8_t> key;
    caf::scoped_actor self;
    self->send(gate, caf::add_atom::value, "127.0.0.1", m_port, key, false);
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

  auto gate2 = caf::io::spawn_io(ranger::proxy::gate_service_impl, 300, std::string());
  scope_guard guard_gate2([gate2] {
    caf::anon_send_exit(gate2, caf::exit_reason::kill);
  });

  {
    std::vector<uint8_t> key;
    caf::scoped_actor self;
    self->send(gate2, caf::add_atom::value, "127.0.0.1", port, key, false);
    self->sync_send(gate2, caf::publish_atom::value, static_cast<uint16_t>(0)).await(
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

  char buf[] = "Hello, world!";
  ASSERT_EQ(sizeof(buf), send(fd, buf, sizeof(buf), 0));
  memset(buf, 0, sizeof(buf));
  ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
  EXPECT_STREQ("Hello, world!", buf);
}

TEST_F(ranger_proxy_test, gate_null) {
  auto gate = caf::io::spawn_io(ranger::proxy::gate_service_impl, 300, std::string());
  scope_guard guard_gate([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });

  uint16_t port = 0;
  {
    std::vector<uint8_t> key;
    caf::scoped_actor self;
    self->send(gate, caf::add_atom::value, "127.0.0.1", static_cast<uint16_t>(0x7FFF), key, false);
    self->sync_send(gate, caf::publish_atom::value, port).await(
      [&port] (caf::ok_atom, uint16_t gate_port) {
        port = gate_port;
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
  }

  caf::detail::singletons::get_actor_registry()->await_running_count_equal(1);
}
