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

#ifndef RANGER_PROXY_TUNNEL_SERVER_SESSION_HPP
#define RANGER_PROXY_TUNNEL_SERVER_SESSION_HPP

#include <map>

namespace ranger { namespace proxy { namespace experimental {

using tunnel_server_session = minimal_client;

class tunnel_server_state {
public:
	tunnel_server_state(tunnel_server_session::broker_pointer self);

	tunnel_server_state(const tunnel_server_state&) = delete;
	tunnel_server_state& operator = (const tunnel_server_state&) = delete;

	void init(connection_handle hdl, const std::string& host, uint16_t port);
	
	void handle_new_data(const new_data_msg& msg);
	void handle_conn_closed(const connection_closed_msg& msg);

private:
	const tunnel_server_session::broker_pointer m_self;
	connection_handle m_local_hdl;
	std::string m_host;
	uint16_t m_port {0};
	connection_handle m_remote_hdl;
	std::map<int64_t, connection_handle> m_id_to_hdl;
	std::map<connection_handle, int64_t> m_hdl_to_id;
};

tunnel_server_session::behavior_type
tunnel_server_session_impl(	tunnel_server_session::stateful_broker_pointer<tunnel_server_state> self,
							connection_handle hdl, const std::string& host, uint16_t port);

} } }

#endif	// RANGER_PROXY_TUNNEL_SERVER_SESSION_HPP
