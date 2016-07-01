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

#ifndef TEST_UTIL_HPP
#define TEST_UTIL_HPP

#include <caf/all.hpp>
#include <caf/io/all.hpp>
#include <caf/io/network/asio_multiplexer_impl.hpp>
#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include <memory>
#include "scope_guard.hpp"

using echo_service =
  caf::io::accept_handler::extend_with<caf::io::connection_handler>::extend<
    caf::replies_to<caf::publish_atom>::with<uint16_t>
  >;

echo_service::behavior_type
echo_service_impl(echo_service::broker_pointer self) {
  return {
    [=] (const caf::io::new_connection_msg& msg) {
      self->configure_read(msg.handle, caf::io::receive_policy::at_most(8192));
    },
    [=] (const caf::io::new_data_msg& msg) {
      self->write(msg.handle, msg.buf.size(), msg.buf.data());
      self->flush(msg.handle);
      self->close(msg.handle);
    },
    [] (const caf::io::connection_closed_msg&) {},
    [] (const caf::io::acceptor_closed_msg&) {},
    [=] (caf::publish_atom) -> caf::result<uint16_t> {
      auto result = self->add_tcp_doorman();
      if (result) {
        return result->second;
      } else {
        return result.error();
      }
    }
  };
}

class ranger_proxy_test : public testing::Test {
public:
  ranger_proxy_test() {
    m_cfg.middleman_network_backend = caf::atom("asio");
    m_cfg.load<caf::io::middleman>();
    m_sys.reset(new caf::actor_system(m_cfg));
  }

protected:
  void TearDown() override {
    m_sys->await_all_actors_done();
  }

  caf::actor_system_config m_cfg;
  std::unique_ptr<caf::actor_system> m_sys;
};

class echo_test : public ranger_proxy_test {
protected:
  void SetUp() final {
    m_echo = m_sys->middleman().spawn_broker(echo_service_impl);
    auto echo_fv = caf::make_function_view(m_echo);
    m_port = *echo_fv(caf::publish_atom::value);
    ASSERT_NE(0, m_port);
  }

  void TearDown() final {
    caf::anon_send_exit(m_echo, caf::exit_reason::kill);
    ranger_proxy_test::TearDown();
  }

  echo_service m_echo = caf::unsafe_actor_handle_init;
  uint16_t m_port {0};
};

using ranger::proxy::make_scope_guard;

#endif  // TEST_UTIL_HPP
