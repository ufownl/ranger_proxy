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
#include "err.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

TEST_F(echo_test, gate_echo) {
  auto gate = m_sys->middleman().spawn_broker(ranger::proxy::gate_service_impl, 300, std::string());
  auto gate_guard = make_scope_guard([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });
  auto gate_fv = caf::make_function_view(gate);

  gate_fv(caf::add_atom::value, "127.0.0.1", m_port,
          std::vector<uint8_t>(), false);
  auto port = gate_fv(caf::publish_atom::value, static_cast<uint16_t>(0));
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  auto guard_fd = make_scope_guard([fd] { close(fd); });

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
  auto gate = m_sys->middleman().spawn_broker(ranger::proxy::gate_service_impl, 300, std::string());
  auto gate_guard = make_scope_guard([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });
  auto gate_fv = caf::make_function_view(gate);

  gate_fv(caf::add_atom::value, "127.0.0.1", m_port,
          std::vector<uint8_t>(), false);
  auto port = gate_fv(caf::publish_atom::value, static_cast<uint16_t>(0));
  ASSERT_NE(0, port);

  auto gate2 =
    m_sys->middleman().spawn_broker(ranger::proxy::gate_service_impl,
                                    300, std::string());
  auto gate2_guard = make_scope_guard([gate2] {
    caf::anon_send_exit(gate2, caf::exit_reason::kill);
  });
  auto gate2_fv = caf::make_function_view(gate2);

  gate2_fv(caf::add_atom::value, "127.0.0.1", port,
           std::vector<uint8_t>(), false);
  port = gate2_fv(caf::publish_atom::value, static_cast<uint16_t>(0));
  ASSERT_NE(0, port);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_NE(-1, fd);
  auto guard_fd = make_scope_guard([fd] { close(fd); });

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
  auto gate = m_sys->middleman().spawn_broker(ranger::proxy::gate_service_impl, 300, std::string());
  auto gate_guard = make_scope_guard([gate] {
    caf::anon_send_exit(gate, caf::exit_reason::kill);
  });
  auto gate_fv = caf::make_function_view(gate);

  gate_fv(caf::add_atom::value, "127.0.0.1", static_cast<uint16_t>(0x7FFF),
          std::vector<uint8_t>(), false);
  auto port = gate_fv(caf::publish_atom::value, static_cast<uint16_t>(0));
  ASSERT_NE(0, port);

  for (auto i = 0; i < 10; ++i) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(-1, fd);
    auto guard_fd = make_scope_guard([fd] { close(fd); });

    sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(port);
    ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));
  }

  gate_fv.assign(caf::invalid_actor);
  m_sys->registry().await_running_count_equal(1);
}
