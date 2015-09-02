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

#ifndef RANGER_PROXY_TUNNEL_SERVER_SERVICE_HPP
#define RANGER_PROXY_TUNNEL_SERVER_SERVICE_HPP

namespace ranger { namespace proxy {

using tunnel_server_service =
	minimal_server::extend<
		replies_to<publish_atom, uint16_t>
			::with_either<ok_atom, uint16_t>
			::or_else<error_atom, std::string>,
		replies_to<publish_atom, std::string, uint16_t>
			::with_either<ok_atom, uint16_t>
			::or_else<error_atom, std::string>
	>;

tunnel_server_service::behavior_type
tunnel_server_service_impl(	tunnel_server_service::broker_pointer self,
							const std::string& host, uint16_t port);

} }

#endif	// RANGER_PROXY_TUNNEL_SERVER_SERVICE_HPP
