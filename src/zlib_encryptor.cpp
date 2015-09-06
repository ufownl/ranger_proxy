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
#include "zlib_encryptor.hpp"
#include <string.h>

namespace ranger { namespace proxy {

zlib_state::zlib_state(encryptor::pointer self)
	: m_self(self) {
	// nop
}

zlib_state::~zlib_state() {
	if (m_encryptor) {
		anon_send_exit(m_encryptor, exit_reason::user_shutdown);
	}
}

void zlib_state::init(const encryptor& enc) {
	m_encryptor = enc;
	m_unpacker.expect(sizeof(data_header), [this] (std::vector<char> buf) {
		return handle_unpacked_data(std::move(buf));
	});
}

std::vector<char> zlib_state::encrypt(const std::vector<char>& in) const {
	auto dest_len = compressBound(in.size());
	std::vector<char> out(dest_len + sizeof(data_header));
	auto res = compress(reinterpret_cast<Bytef*>(out.data() + sizeof(data_header)), &dest_len,
						reinterpret_cast<const Bytef*>(in.data()), in.size());
	switch (res) {
	case Z_MEM_ERROR:
		aout(m_self) << "ERROR: [Zlib] There was not enough memory" << std::endl;
		return {};
	case Z_BUF_ERROR:
		aout(m_self) << "ERROR: [Zlib] There was not enough room in the output buffer" << std::endl;
		return {};
	}

	out.resize(dest_len + sizeof(data_header));

	data_header header;
	header.compressed_len = dest_len;
	header.origin_len = in.size();
	memcpy(out.data(), &header, sizeof(header));

	if (m_encryptor) {
		scoped_actor self;
		self->sync_send(m_encryptor, encrypt_atom::value, out).await(
			[&out] (encrypt_atom, const std::vector<char>& buf) {
				out = buf;
			}
		);
	}

	return out;
}

std::vector<char> zlib_state::decrypt(const std::vector<char>& in) {
	if (m_encryptor) {
		scoped_actor self;
		self->sync_send(m_encryptor, decrypt_atom::value, in).await(
			[this] (decrypt_atom, const std::vector<char>& buf) {
				m_unpacker.append(buf);
			}
		);
	} else {
		m_unpacker.append(in);
	}

	return std::move(m_origin_buf);
}

bool zlib_state::handle_unpacked_data(std::vector<char> src_buf) {
	if (m_origin_len == 0) {
		const data_header* header = reinterpret_cast<data_header*>(src_buf.data());
		m_origin_len = header->origin_len;
		m_unpacker.expect(header->compressed_len, [this] (std::vector<char> buf) {
			return handle_unpacked_data(std::move(buf));
		});
	} else {
		uLongf dst_len = m_origin_len;
		std::vector<char> dst_buf(dst_len);
		auto res = uncompress(	reinterpret_cast<Bytef*>(dst_buf.data()), &dst_len,
								reinterpret_cast<const Bytef*>(src_buf.data()), src_buf.size());
		switch (res) {
		case Z_MEM_ERROR:
			aout(m_self) << "ERROR: [Zlib] There was not enough memory" << std::endl;
			return false;
		case Z_BUF_ERROR:
			aout(m_self) << "ERROR: [Zlib] There was not enough room in the output buffer" << std::endl;
			return false;
		case Z_DATA_ERROR:
			aout(m_self) << "ERROR: [Zlib] The input data was corrupted or incomplete" << std::endl;
			return false;
		}

		m_origin_buf.insert(m_origin_buf.end(), dst_buf.begin(), dst_buf.end());
		m_origin_len = 0;

		m_unpacker.expect(sizeof(data_header), [this] (std::vector<char> buf) {
			return handle_unpacked_data(std::move(buf));
		});
	}

	return true;
}

encryptor::behavior_type
zlib_encryptor_impl(encryptor::stateful_pointer<zlib_state> self, encryptor enc) {
	self->state.init(enc);
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
