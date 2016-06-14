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

#ifndef RANGER_PROXY_GATE_SESSION_HPP
#define RANGER_PROXY_GATE_SESSION_HPP

#include <vector>
#include "deadline_timer.hpp"
#include "encryptor.hpp"
#include "unpacker.hpp"

namespace ranger { namespace proxy {

using gate_session =
  connection_handler::extend<
    reacts_to<connection_handle>,
    reacts_to<connect_atom, error>,
    reacts_to<encrypt_atom, std::vector<char>>,
    reacts_to<decrypt_atom, std::vector<char>>
  >;

class gate_state {
public:
  gate_state(gate_session::broker_pointer self);

  gate_state(const gate_state&) = delete;
  gate_state& operator = (const gate_state&) = delete;

  void init(connection_handle hdl, const std::string& host, uint16_t port,
            const std::vector<uint8_t>& key, bool zlib, size_t timeout);

  void handle_new_data(const new_data_msg& msg);
  void handle_conn_closed(const connection_closed_msg& msg);
  void handle_connect_succ(connection_handle hdl);
  void handle_connect_fail(const caf::message& what);
  void handle_encrypted_data(const std::vector<char>& buf);
  void handle_decrypted_data(const std::vector<char>& buf);

private:
  const gate_session::broker_pointer m_self;
  deadline_timer m_timer = unsafe_actor_handle_init;
  connection_handle m_local_hdl;
  connection_handle m_remote_hdl;
  std::vector<uint8_t> m_key;
  bool m_zlib {false};
  encryptor m_encryptor = unsafe_actor_handle_init;
  size_t m_decrypting {0};
  std::vector<char> m_buf;
  unpacker<uint8_t> m_unpacker;
};

gate_session::behavior_type
gate_session_impl(gate_session::stateful_broker_pointer<gate_state> self,
                  connection_handle hdl, const std::string& host, uint16_t port,
                  const std::vector<uint8_t>& key, bool zlib, size_t timeout);

} }

#endif  // RANGER_PROXY_GATE_SESSION_HPP
