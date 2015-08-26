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

#include <functional>

namespace ranger { namespace proxy {

using socks5_session =
	minimal_client::extend<
		reacts_to<ok_atom, connection_handle>,
		reacts_to<error_atom, std::string>
	>;

class socks5_handler {
public:
	socks5_handler(socks5_session::broker_pointer self);

	void init(connection_handle hdl);
	void handle_new_data(connection_handle hdl, const new_data_msg& msg);
	void handle_connect_succ(connection_handle hdl);
	void handle_connect_fail(const std::string& what);

private:
	using new_data_handler = void (socks5_handler::*)(connection_handle, const new_data_msg&);

	void handle_select_method_header(connection_handle hdl, const new_data_msg& msg);
	void handle_select_method_data(connection_handle hdl, const new_data_msg& msg);
	void handle_request_header(connection_handle hdl, const new_data_msg& msg);
	void handle_ipv4_request_data(connection_handle hdl, const new_data_msg& msg);
	void handle_domainname_length(connection_handle hdl, const new_data_msg& msg);
	void handle_domainname_request_data(connection_handle hdl, const new_data_msg& msg);
	void handle_stream_data(connection_handle hdl, const new_data_msg& msg);

	socks5_session::broker_pointer m_self;
	connection_handle m_remote_hdl;
	new_data_handler m_current_handler {nullptr};
	std::function<void(connection_handle)> m_conn_succ_handler;
	std::function<void(const std::string&)> m_conn_fail_handler;
};

socks5_session::behavior_type
socks5_session_impl(socks5_session::stateful_broker_pointer<socks5_handler> self, connection_handle hdl);

} }

#endif	// RANGER_PROXY_SOCKS5_SESSION_HPP
