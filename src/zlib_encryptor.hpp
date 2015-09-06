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

#ifndef RANGER_PROXY_ZLIB_ENCRYPTOR_HPP
#define RANGER_PROXY_ZLIB_ENCRYPTOR_HPP

#include "encryptor.hpp"
#include <vector>
#include <queue>
#include <zlib.h>

namespace ranger { namespace proxy {

class zlib_state {
public:
	zlib_state(encryptor::pointer self);
	~zlib_state();

	zlib_state(const zlib_state&) = delete;
	zlib_state& operator = (const zlib_state&) = delete;

	void init(const encryptor& enc);

	std::vector<char> encrypt(const std::vector<char>& in) const;
	std::vector<char> decrypt(const std::vector<char>& in);

private:
	struct data_header {
		uint16_t compressed_len;
		uint16_t origin_len;
	};

	encryptor::pointer m_self;
	encryptor m_encryptor;
	std::queue<std::vector<char>> m_buffers;
	size_t m_current_len {0};
	uint16_t m_offset {0};
	uint16_t m_expected_len {sizeof(data_header)};
	uint16_t m_origin_len {0};
};

encryptor::behavior_type
zlib_encryptor_impl(encryptor::stateful_pointer<zlib_state> self, encryptor enc);

} }

#endif	// RANGER_PROXY_ZLIB_ENCRYPTOR_HPP
