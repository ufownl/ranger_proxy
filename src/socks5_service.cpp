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
#include "socks5_service.hpp"
#include "socks5_session.hpp"
#include "logger_ostream.hpp"
#include "err.hpp"
#include <random>

namespace ranger { namespace proxy {

void socks5_service_state::set_user_table(const user_table& tbl) {
  m_user_tbl = tbl;
}

const user_table& socks5_service_state::get_user_table() const {
  return m_user_tbl;
}

void socks5_service_state::add_doorman_info(accept_handle hdl,
                                            const std::vector<uint8_t>& key,
                                            bool zlib) {
  auto& info = m_info_map[hdl];
  info.first = key;
  info.second = zlib;
}

socks5_service_state::doorman_info
socks5_service_state::get_doorman_info(accept_handle hdl) const {
  auto it = m_info_map.find(hdl);
  if (it == m_info_map.end()) {
    return {{}, false};
  } else {
    return it->second;
  }
}

socks5_service::behavior_type
socks5_service_impl(socks5_service::stateful_broker_pointer<socks5_service_state> self,
                    size_t timeout, bool verbose, const std::string& log) {
  self->set_exit_handler([self, verbose] (const exit_msg& msg) {
    if (msg.reason != exit_reason::normal
        && msg.reason != exit_reason::user_shutdown
        && msg.reason != exit_reason::unhandled_exception) {
      self->quit(msg.reason);
    } else {
      --self->state.session_count;
      if (verbose) {
        ranger::proxy::log(self) << "INFO: Remained socks5 session count: " 
                                 << self->state.session_count << std::endl;
      }
    }
  });

  if (!log.empty()) {
    logger_ostream::redirect(self->spawn<linked>(logger_impl, log));
  }

  std::random_device dev;
  std::minstd_rand rd(dev());
  return {
    [rd, self, timeout, verbose] (const new_connection_msg& msg) mutable {
      auto info = self->state.get_doorman_info(msg.source);
      uint32_t seed = 0;
      if (!info.first.empty()) {
        seed = rd();
        if (verbose) {
          ranger::proxy::log(self) << "INFO: Initialization vector seed[" << seed << "]" << std::endl;
        }

        self->write(msg.handle, sizeof(seed), &seed);
        self->flush(msg.handle);
      }

      auto forked =
        self->fork(socks5_session_impl, msg.handle,
                   self->state.get_user_table(),
                   info.first, seed, info.second,
                   timeout, verbose);
      self->link_to(forked);
      ++self->state.session_count;
    },
    [] (const acceptor_closed_msg&) {},
    [self] (publish_atom, uint16_t port,
            const std::vector<uint8_t>& key, bool zlib) -> result<uint16_t> {
      try {
        auto doorman = self->add_tcp_doorman(port, nullptr, true);
        if (doorman) {
          self->state.add_doorman_info(doorman->first, key, zlib);
          return doorman->second;
        } else {
          return doorman.error();
        }
      } catch (const std::exception& e) {
        return make_error(err::unknown, e.what());
      }
    },
    [self] (publish_atom, const std::string& host, uint16_t port,
            const std::vector<uint8_t>& key, bool zlib) -> result<uint16_t> {
      try {
        auto doorman = self->add_tcp_doorman(port, host.c_str(), true);
        if (doorman) {
          self->state.add_doorman_info(doorman->first, key, zlib);
          return doorman->second;
        } else {
          return doorman.error();
        }
      } catch (const std::exception& e) {
        return make_error(err::unknown, e.what());
      }
    },
    [self] (add_atom, const std::string& username, const std::string& password) {
      auto tbl = self->state.get_user_table();
      if (tbl.unsafe()) {
        tbl = self->spawn<linked>(user_table_impl);
        self->state.set_user_table(tbl);
      }

      return self->delegate(tbl, add_atom::value, username, password);
    },
  };
}

} }
