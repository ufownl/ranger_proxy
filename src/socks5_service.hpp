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

#ifndef RANGER_PROXY_SOCKS5_SERVICE_HPP
#define RANGER_PROXY_SOCKS5_SERVICE_HPP

#include <string>
#include <vector>
#include "user_table.hpp"
#include "encryptor.hpp"

namespace ranger { namespace proxy {

using zlib_atom = atom_constant<atom("zlib")>;

using socks5_service =
	minimal_server::extend<
		replies_to<publish_atom, uint16_t>
			::with_either<ok_atom, uint16_t>
			::or_else<error_atom, std::string>,
		replies_to<publish_atom, std::string, uint16_t>
			::with_either<ok_atom, uint16_t>
			::or_else<error_atom, std::string>,
		replies_to<add_atom, std::string, std::string>::with<bool, std::string>,
		reacts_to<encrypt_atom, std::vector<uint8_t>, std::vector<uint8_t>>,
		reacts_to<zlib_atom, bool>
	>;

class socks5_service_state {
public:
	socks5_service_state() = default;

	socks5_service_state(const socks5_service_state&) = delete;
	socks5_service_state& operator = (const socks5_service_state&) = delete;

	void set_user_table(const user_table& tbl);
	const user_table& get_user_table() const;

	void set_key(const std::vector<uint8_t>& key);
	void set_ivec(const std::vector<uint8_t>& ivec);
	void set_zlib(bool zlib);

	encryptor spawn_encryptor() const;

private:
	user_table m_user_tbl;
	std::vector<uint8_t> m_key;
	std::vector<uint8_t> m_ivec;
	bool m_zlib {false};
};

socks5_service::behavior_type
socks5_service_impl(socks5_service::stateful_broker_pointer<socks5_service_state> self, bool verbose);

} }

#endif	// RANGER_PROXY_SOCKS5_SERVICE_HPP
