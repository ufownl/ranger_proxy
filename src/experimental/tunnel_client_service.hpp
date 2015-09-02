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

#ifndef RANGER_PROXY_TUNNEL_CLIENT_SERVICE_HPP
#define RANGER_PROXY_TUNNEL_CLIENT_SERVICE_HPP

namespace ranger { namespace proxy { namespace experimental {

using tunnel_client_service =
	minimal_server::extend<
		replies_to<publish_atom>
			::with_either<ok_atom, uint16_t>
			::or_else<error_atom, std::string>
	>;

class tunnel_client_state {
public:
	tunnel_client_state(tunnel_client_service::broker_pointer self);

	tunnel_client_state(const tunnel_client_service&) = delete;
	tunnel_client_state& operator = (const tunnel_client_service&) = delete;

	void init(connection_handle hdl);

	void handle_new_data(const new_data_msg& msg);
	void handle_new_conn(const new_connection_msg& msg);
	void handle_conn_closed(const connection_closed_msg& msg);

private:
	const tunnel_client_service::broker_pointer m_self;
	connection_handle m_local_hdl;
	connection_handle m_remote_hdl;
};

tunnel_client_service::behavior_type
tunnel_client_service_impl(	tunnel_client_service::stateful_broker_pointer<tunnel_client_state> self,
							connection_handle hdl);

} } }

#endif	// RANGER_PROXY_TUNNEL_CLIENT_SERVICE_HPP
