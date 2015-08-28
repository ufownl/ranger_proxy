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
#include "connect_helper.hpp"

namespace ranger { namespace proxy {

connect_helper::behavior_type
connect_helper_impl(connect_helper::pointer self, network::multiplexer* backend) {
	return {
		[=] (connect_atom, const std::string& host, uint16_t port)
			-> either<ok_atom, connection_handle>::or_else<error_atom, std::string> {
			self->quit();
			try {
				return {ok_atom::value, backend->new_tcp_scribe(host, port)};
			} catch (const network_error& e) {
				return {error_atom::value, e.what()};
			}
		}
	};
}

} }
