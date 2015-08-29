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
#include "encryptor.hpp"

namespace ranger { namespace proxy {

using gate_session =
	minimal_client::extend<
		reacts_to<ok_atom, connection_handle>,
		reacts_to<error_atom, std::string>,
		reacts_to<encrypt_atom, std::vector<char>>,
		reacts_to<decrypt_atom, std::vector<char>>
	>;

class gate_state {
public:
	gate_state(gate_session::broker_pointer self);
	~gate_state();

	gate_state(const gate_state&) = delete;
	gate_state& operator = (const gate_state&) = delete;

	void init(connection_handle hdl, const std::string& host, uint16_t port, encryptor enc);

	void handle_new_data(const new_data_msg& msg);
	void handle_encrypted_data(const std::vector<char>& buf);
	void handle_decrypted_data(const std::vector<char>& buf);

	void handle_connect_succ(connection_handle hdl);
	void handle_connect_fail(const std::string& what);

private:
	const gate_session::broker_pointer m_self;
	connection_handle m_local_hdl;
	connection_handle m_remote_hdl;
	encryptor m_encryptor;
	std::vector<char> m_buf;
};

gate_session::behavior_type
gate_session_impl(	gate_session::stateful_broker_pointer<gate_state> self,
					connection_handle hdl, const std::string& host, uint16_t port, encryptor enc);

} }

#endif	// RANGER_PROXY_GATE_SESSION_HPP
