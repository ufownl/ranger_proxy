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
#include "gate_service.hpp"
#include "gate_session.hpp"

namespace ranger { namespace proxy {

void gate_service_state::add_host(host_info host) {
	if (!host.addr.empty() && host.port != 0) {
		m_hosts.emplace_back(std::move(host));
	}
}

gate_service_state::host_info gate_service_state::query_host() {
	if (m_hosts.empty()) {
		return {"", 0};
	}

	if (!m_dist) {
		std::random_device rd;
		m_rand_engine.reset(new std::minstd_rand(rd()));
		m_dist.reset(new std::uniform_int_distribution<size_t>(0, m_hosts.size() - 1));
	} else if (m_dist->max() != m_hosts.size() - 1) {
		m_dist.reset(new std::uniform_int_distribution<size_t>(0, m_hosts.size() - 1));
	}

	return m_hosts[(*m_dist)(*m_rand_engine)];
}

gate_service::behavior_type
gate_service_impl(gate_service::stateful_broker_pointer<gate_service_state> self, int timeout) {
	return {
		[=] (const new_connection_msg& msg) {
			auto host = self->state.query_host();
			if (host.port != 0) {
				auto forked =
					self->fork(	gate_session_impl, msg.handle, host.addr, host.port,
								host.key, host.zlib, timeout);
				self->link_to(forked);
			} else {
				aout(self) << "ERROR: Hosts list is empty" << std::endl;
				self->close(msg.handle);
			}
		},
		[] (const new_data_msg&) {},
		[] (const connection_closed_msg&) {},
		[] (const acceptor_closed_msg&) {},
		[self] (publish_atom, uint16_t port)
			-> either<ok_atom, uint16_t>::or_else<error_atom, std::string> {
			try {
				return {
					ok_atom::value,
					self->add_tcp_doorman(port, nullptr, true).second
				};
			} catch (const network_error& e) {
				return {error_atom::value, e.what()};
			}
		},
		[self] (publish_atom, const std::string& host, uint16_t port)
			-> either<ok_atom, uint16_t>::or_else<error_atom, std::string> {
			try {
				return {
					ok_atom::value,
					self->add_tcp_doorman(port, host.c_str(), true).second
				};
			} catch (const network_error& e) {
				return {error_atom::value, e.what()};
			}
		},
		[self] (add_atom, const std::string& addr, uint16_t port,
				const std::vector<uint8_t>& key, bool zlib) {
			gate_service_state::host_info host;
			host.addr = addr;
			host.port = port;
			host.key = key;
			host.zlib = zlib;
			self->state.add_host(std::move(host));
		}
	};
}

} }
