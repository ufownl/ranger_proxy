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
#include "socks5_service.hpp"
#include "socks5_session.hpp"
#include "aes_cfb128_encryptor.hpp"
#include "zlib_encryptor.hpp"

namespace ranger { namespace proxy {

void socks5_service_state::set_user_table(const user_table& tbl) {
	m_user_tbl = tbl;
}

const user_table& socks5_service_state::get_user_table() const {
	return m_user_tbl;
}

void socks5_service_state::set_key(const std::vector<uint8_t>& key) {
	m_key = key;
}

void socks5_service_state::set_ivec(const std::vector<uint8_t>& ivec) {
	m_ivec = ivec;
}

void socks5_service_state::set_zlib(bool zlib) {
	m_zlib = zlib;
}

encryptor socks5_service_state::spawn_encryptor() const {
	encryptor enc;
	if (!m_key.empty() || !m_ivec.empty()) {
		enc = spawn(aes_cfb128_encryptor_impl, m_key, m_ivec);
	}
	if (m_zlib) {
		enc = spawn(zlib_encryptor_impl, enc);
	}
	return enc;
}

socks5_service::behavior_type
socks5_service_impl(socks5_service::stateful_broker_pointer<socks5_service_state> self, bool verbose) {
	return {
		[self, verbose] (const new_connection_msg& msg) {
			auto forked =
				self->fork(	socks5_session_impl, msg.handle,
							self->state.get_user_table(),
							self->state.spawn_encryptor(),
							verbose);
			self->link_to(forked);
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
		[self] (add_atom, const std::string& username, const std::string& password) {
			auto tbl = self->state.get_user_table();
			if (!tbl) {
				tbl = self->spawn<linked>(user_table_impl);
				self->state.set_user_table(tbl);
			}

			return self->delegate(tbl, add_atom::value, username, password);
		},
		[self] (encrypt_atom, const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivec) {
			self->state.set_key(key);
			self->state.set_ivec(ivec);
		},
		[self] (zlib_atom, bool zlib) {
			self->state.set_zlib(zlib);
		}
	};
}

} }
