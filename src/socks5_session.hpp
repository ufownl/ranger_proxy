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
#include "user_table.hpp"
#include "encryptor.hpp"

namespace ranger { namespace proxy {

using socks5_session =
	minimal_client::extend<
		reacts_to<ok_atom, connection_handle>,
		reacts_to<error_atom, std::string>,
		reacts_to<encrypt_atom, std::vector<char>>,
		reacts_to<decrypt_atom, std::vector<char>>,
		reacts_to<close_atom>
	>;

class socks5_state {
public:
	socks5_state(socks5_session::broker_pointer self);
	~socks5_state();

	socks5_state(const socks5_state&) = delete;
	socks5_state& operator = (const socks5_state&) = delete;

	void init(connection_handle hdl, user_table tbl, encryptor enc, bool verbose);

	void handle_new_data(const new_data_msg& msg);
	void handle_conn_closed(const connection_closed_msg& msg);
	void handle_connect_succ(connection_handle hdl);
	void handle_connect_fail(const std::string& what);
	void handle_encrypted_data(const std::vector<char>& buf);
	void handle_decrypted_data(const std::vector<char>& buf);

private:
	void write_to_local(std::vector<char> buf) const;
	void write_to_remote(std::vector<char> buf) const;
	void write_raw(connection_handle hdl, std::vector<char> buf) const;

	void handle_select_method(const new_data_msg& msg);
	void handle_username_auth(const new_data_msg& msg);
	void handle_auth_result(bool result);
	void handle_request_header(const new_data_msg& msg);
	void handle_ipv4_request(const new_data_msg& msg);
	void handle_domainname_request(const new_data_msg& msg);
	void handle_stream_data(const new_data_msg& msg);

	const socks5_session::broker_pointer m_self;
	connection_handle m_local_hdl;
	connection_handle m_remote_hdl;
	user_table m_user_tbl;
	encryptor m_encryptor;
	bool m_verbose {false};
	bool m_valid_handler {false};
	std::function<void(const new_data_msg&)> m_current_handler;
	std::function<void(connection_handle)> m_conn_succ_handler;
	std::function<void(const std::string&)> m_conn_fail_handler;
};

socks5_session::behavior_type
socks5_session_impl(socks5_session::stateful_broker_pointer<socks5_state> self,
					connection_handle hdl, user_table tbl, encryptor enc, bool verbose);

} }

#endif	// RANGER_PROXY_SOCKS5_SESSION_HPP
