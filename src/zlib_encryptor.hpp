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
#include <zlib.h>

namespace ranger { namespace proxy {

class zlib_state {
public:
	using encrypt_promise_type =
		typed_response_promise<encrypt_atom, std::vector<char>>;

	using decrypt_promise_type =
		typed_response_promise<decrypt_atom, std::vector<char>>;

	zlib_state(encryptor::pointer self);
	~zlib_state();

	zlib_state(const zlib_state&) = delete;
	zlib_state& operator = (const zlib_state&) = delete;

	void init(const encryptor& enc);

	encrypt_promise_type encrypt(const std::vector<char>& in);
	decrypt_promise_type decrypt(const std::vector<char>& in);

private:
	std::vector<char> compress(const std::vector<char>& in);
	std::vector<char> uncompress(const std::vector<char>& in);

	encryptor::pointer m_self;
	encryptor m_encryptor;
	z_stream m_deflate_strm {0};
	z_stream m_inflate_strm {0};
};

encryptor::behavior_type
zlib_encryptor_impl(encryptor::stateful_pointer<zlib_state> self, encryptor enc);

} }

#endif	// RANGER_PROXY_ZLIB_ENCRYPTOR_HPP
