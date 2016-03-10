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

#include "common.hpp"
#include "gate_service.hpp"
#include "gate_session.hpp"
#include "logger_ostream.hpp"
#include "err.hpp"

namespace ranger { namespace proxy {

void gate_service_state::add_host(host_info host) {
  if (!host.addr.empty() && host.port != 0) {
    m_hosts.emplace_back(std::move(host));
  }
}

gate_service_state::host_info gate_service_state::query_host() {
  if (m_hosts.empty()) {
    return {"", 0};
  }

  if (!m_dist) {
    std::random_device rd;
    m_rand_engine.reset(new std::minstd_rand(rd()));
    m_dist.reset(new std::uniform_int_distribution<size_t>(0, m_hosts.size() - 1));
  } else if (m_dist->max() != m_hosts.size() - 1) {
    m_dist.reset(new std::uniform_int_distribution<size_t>(0, m_hosts.size() - 1));
  }

  return m_hosts[(*m_dist)(*m_rand_engine)];
}

gate_service::behavior_type
gate_service_impl(gate_service::stateful_broker_pointer<gate_service_state> self,
                  int timeout, const std::string& log) {
  self->trap_exit(true);

  if (!log.empty()) {
    logger_ostream::redirect(self->spawn<linked>(logger_impl, log));
  }

  return {
    [self, timeout] (const new_connection_msg& msg) {
      auto host = self->state.query_host();
      if (host.port != 0) {
        auto forked =
          self->fork(gate_session_impl, msg.handle, host.addr, host.port,
                     host.key, host.zlib, timeout);
        self->link_to(forked);
      } else {
        ranger::proxy::log(self) << "ERROR: Hosts list is empty" << std::endl;
        self->close(msg.handle);
      }
    },
    [] (const acceptor_closed_msg&) {},
    [self] (publish_atom, uint16_t port) -> maybe<uint16_t> {
      try {
        return self->add_tcp_doorman(port, nullptr, true).second;
      } catch (const network_error& e) {
        return make_error(err::network_error, e.what());
      }
    },
    [self] (publish_atom, const std::string& host, uint16_t port) -> maybe<uint16_t> {
      try {
        return self->add_tcp_doorman(port, host.c_str(), true).second;
      } catch (const network_error& e) {
        return make_error(err::network_error, e.what());
      }
    },
    [self] (add_atom, const std::string& addr, uint16_t port,
            const std::vector<uint8_t>& key, bool zlib) {
      gate_service_state::host_info host;
      host.addr = addr;
      host.port = port;
      host.key = key;
      host.zlib = zlib;
      self->state.add_host(std::move(host));
    },
    [self] (const exit_msg& msg) {
      if (msg.reason != exit_reason::normal
          && msg.reason != exit_reason::user_shutdown
          && msg.reason != exit_reason::unhandled_exception) {
        self->quit(msg.reason);
      }
    }
  };
}

} }
