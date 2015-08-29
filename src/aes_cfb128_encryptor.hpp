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

#ifndef RANGER_PROXY_AES_CFB128_ENCRYPTOR_HPP
#define RANGER_PROXY_AES_CFB128_ENCRYPTOR_HPP

#include "encryptor.hpp"
#include <openssl/aes.h>

namespace ranger { namespace proxy {

class aes_cfb128_state {
public:
	aes_cfb128_state() = default;

	aes_cfb128_state(const aes_cfb128_state&) = delete;
	aes_cfb128_state& operator = (const aes_cfb128_state&) = delete;

	void init(std::vector<uint8_t> key, std::vector<uint8_t> ivec);

	std::vector<char> encrypt(const std::vector<char>& in);
	std::vector<char> decrypt(const std::vector<char>& in);

private:
	AES_KEY m_key {0};
	std::vector<uint8_t> m_encrypt_ivec;
	int m_encrypt_num {0};
	std::vector<uint8_t> m_decrypt_ivec;
	int m_decrypt_num {0};
};

encryptor::behavior_type
aes_cfb128_encryptor_impl(	encryptor::stateful_pointer<aes_cfb128_state> self,
							const std::vector<uint8_t>& key,
							const std::vector<uint8_t>& ivec);

} }

#endif	// RANGER_PROXY_AES_CFB128_ENCRYPTOR_HPP
