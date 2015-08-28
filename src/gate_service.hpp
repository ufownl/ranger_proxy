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

#ifndef RANGER_PROXY_GATE_SERVICE_HPP
#define RANGER_PROXY_GATE_SERVICE_HPP

#include <string>
#include <vector>
#include <utility>

namespace ranger { namespace proxy {

using gate_service =
	minimal_server::extend<
		replies_to<publish_atom, uint16_t>
		::with_either<ok_atom, uint16_t>
		::or_else<error_atom, std::string>,
		replies_to<publish_atom, std::string, uint16_t>
		::with_either<ok_atom, uint16_t>
		::or_else<error_atom, std::string>,
		reacts_to<add_atom, std::string, uint16_t>
	>;

class gate_service_state {
public:
	gate_service_state() = default;

	gate_service_state(const gate_service_state&) = delete;
	gate_service_state& operator = (const gate_service_state&) = delete;

	void add_host(const std::string& host, uint16_t port);
	std::pair<std::string, uint16_t> query_host();

private:
	std::vector<std::pair<std::string, uint16_t>> m_hosts;
	size_t m_index {0};
};

gate_service::behavior_type
gate_service_impl(gate_service::stateful_broker_pointer<gate_service_state> self);

} }

#endif	// RANGER_PROXY_GATE_SERVICE_HPP
