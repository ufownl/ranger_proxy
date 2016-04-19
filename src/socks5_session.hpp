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

#ifndef RANGER_PROXY_SOCKS5_SESSION_HPP
#define RANGER_PROXY_SOCKS5_SESSION_HPP

#include <string>
#include <vector>
#include <functional>
#include "deadline_timer.hpp"
#include "user_table.hpp"
#include "encryptor.hpp"
#include "unpacker.hpp"

namespace ranger { namespace proxy {

using socks5_session =
  connection_handler::extend<
    reacts_to<connection_handle>,
    reacts_to<error>,
    reacts_to<encrypt_atom, std::vector<char>>,
    reacts_to<decrypt_atom, std::vector<char>>,
    reacts_to<auth_atom, bool>
  >;

class socks5_state {
public:
  socks5_state(socks5_session::broker_pointer self);
  ~socks5_state();

  socks5_state(const socks5_state&) = delete;
  socks5_state& operator = (const socks5_state&) = delete;

  void init(connection_handle hdl,
            const user_table& tbl,
            const std::vector<uint8_t>& key,
            uint32_t seed, bool zlib,
            int timeout, bool verbose);

  void handle_new_data(const new_data_msg& msg);
  void handle_conn_closed(const connection_closed_msg& msg);
  void handle_connect_succ(connection_handle hdl);
  void handle_connect_fail(const caf::message& what);
  void handle_encrypted_data(const std::vector<char>& buf);
  void handle_decrypted_data(const std::vector<char>& buf);
  void handle_auth_result(bool result);
  void handle_user_shutdown(const actor_addr& source);

private:
  void write_to_local(std::vector<char> buf);
  void write_raw(connection_handle hdl, std::vector<char> buf);

  bool handle_select_method(std::vector<char> buf);
  bool handle_username_auth(std::vector<char> buf);
  bool handle_request_header(std::vector<char> buf);
  bool handle_ipv4_request(std::vector<char> buf);
  bool handle_domainname_request(std::vector<char> buf);

  const socks5_session::broker_pointer m_self;
  deadline_timer m_timer;
  connection_handle m_local_hdl;
  size_t m_local_recv_bytes {0};
  size_t m_local_send_bytes {0};
  connection_handle m_remote_hdl;
  size_t m_remote_recv_bytes {0};
  size_t m_remote_send_bytes {0};
  user_table m_user_tbl;
  encryptor m_encryptor;
  size_t m_encrypting {0};
  bool m_verbose {false};
  bool m_valid {false};
  unpacker<uint8_t> m_unpacker;
  std::function<void(connection_handle)> m_conn_succ_handler;
  std::function<void(const caf::message&)> m_conn_fail_handler;
};

socks5_session::behavior_type
socks5_session_impl(socks5_session::stateful_broker_pointer<socks5_state> self,
                    connection_handle hdl, user_table tbl, const std::vector<uint8_t>& key,
                    uint32_t seed, bool zlib, int timeout, bool verbose);

} }

#endif  // RANGER_PROXY_SOCKS5_SESSION_HPP
