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
#include "aes_cfb128_encryptor.hpp"
#include <string.h>

namespace ranger { namespace proxy {

void aes_cfb128_state::init(std::vector<uint8_t> key, std::vector<uint8_t> ivec) {
	if (key.size() * 8 > 192) {
		key.resize(256 / 8);
	} else if (key.size() * 8 > 128) {
		key.resize(192 / 8);
	} else {
		key.resize(128 / 8);
	}
	AES_set_encrypt_key(key.data(), key.size() * 8, &m_key);

	ivec.resize(128 / 8);
	m_encrypt_ivec = ivec;
	m_decrypt_ivec = std::move(ivec);
}

std::vector<char> aes_cfb128_state::encrypt(const std::vector<char>& in) {
	std::vector<char> out(in.size());
	AES_cfb128_encrypt(	reinterpret_cast<const uint8_t*>(in.data()),
						reinterpret_cast<uint8_t*>(out.data()), in.size(),
						&m_key, m_encrypt_ivec.data(), &m_encrypt_num, AES_ENCRYPT);
	return out;
}

std::vector<char> aes_cfb128_state::decrypt(const std::vector<char>& in) {
	std::vector<char> out(in.size());
	AES_cfb128_encrypt(	reinterpret_cast<const uint8_t*>(in.data()),
						reinterpret_cast<uint8_t*>(out.data()), in.size(),
						&m_key, m_decrypt_ivec.data(), &m_decrypt_num, AES_DECRYPT);
	return out;
}

encryptor::behavior_type
aes_cfb128_encryptor_impl(	encryptor::stateful_pointer<aes_cfb128_state> self,
							const std::vector<uint8_t>& key,
							const std::vector<uint8_t>& ivec) {
	self->state.init(key, ivec);
	return {
		[self] (encrypt_atom, const std::vector<char>& data) {
			return std::make_tuple(encrypt_atom::value, self->state.encrypt(data));
		},
		[self] (decrypt_atom, const std::vector<char>& data) {
			return std::make_tuple(decrypt_atom::value, self->state.decrypt(data));
		}
	};
}

} }
