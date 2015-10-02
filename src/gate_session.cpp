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
#include "gate_session.hpp"
#include "aes_cfb128_encryptor.hpp"
#include "zlib_encryptor.hpp"
#include "logger_ostream.hpp"
#include <caf/io/network/asio_multiplexer.hpp>
#include <memory>
#include <chrono>

namespace ranger { namespace proxy {

gate_state::gate_state(gate_session::broker_pointer self)
	: m_self(self) {
	// nop
}

void gate_state::init(	connection_handle hdl, const std::string& host, uint16_t port,
						const std::vector<uint8_t>& key, bool zlib) {
	m_local_hdl = hdl;
	m_self->configure_read(m_local_hdl, receive_policy::at_most(BUFFER_SIZE));

	m_key = key;
	m_zlib = zlib;

	using boost::asio::ip::tcp;
	auto r = std::make_shared<tcp::resolver>(*m_self->parent().backend().pimpl());
	tcp::resolver::query q(host, std::to_string(port));
	using boost::system::error_code;
	r->async_resolve(q, [this, host, port, r] (const error_code& ec, tcp::resolver::iterator it) {
		if (ec) {
			log(m_self) << "ERROR: " << ec.message() << std::endl;
			m_self->send(m_self, error_atom::value, "could not resolve host: " + host);
		} else {
			auto fd = std::make_shared<network::default_socket>(*m_self->parent().backend().pimpl());
			boost::asio::async_connect(*fd, it, [this, host, port, fd] (const error_code& ec, tcp::resolver::iterator it) {
				if (ec) {
					log(m_self) << "ERROR: " << ec.message() << std::endl;
					m_self->send(m_self, error_atom::value, "could not connect to host: " + host + ":" + std::to_string(port));
				} else {
					auto hdl =
						static_cast<network::asio_multiplexer&>(m_self->parent().backend())
							.add_tcp_scribe(m_self, std::move(*fd));
					m_self->send(m_self, ok_atom::value, hdl);
				}
			});
		}
	});
}

void gate_state::handle_new_data(const new_data_msg& msg) {
	if (msg.handle == m_local_hdl) {
		if (m_remote_hdl.invalid()) {
			m_buf.insert(m_buf.end(), msg.buf.begin(), msg.buf.end());
		} else {
			if (!m_key.empty()) {
				if (m_encryptor) {
					m_self->send(m_encryptor, encrypt_atom::value, msg.buf);
				} else {
					m_buf.insert(m_buf.end(), msg.buf.begin(), msg.buf.end());
				}
			} else if (m_self->valid(m_remote_hdl)) {
				m_self->write(m_remote_hdl, msg.buf.size(), msg.buf.data());
				m_self->flush(m_remote_hdl);
			}
		}
	} else {
		if (!m_key.empty()) {
			if (m_encryptor) {
				m_self->send(m_encryptor, decrypt_atom::value, msg.buf);
				++m_decrypting;
			} else {
				m_unpacker.append(msg.buf);
			}
		} else {
			m_self->write(m_local_hdl, msg.buf.size(), msg.buf.data());
			m_self->flush(m_local_hdl);
		}
	}
}

void gate_state::handle_conn_closed(const connection_closed_msg& msg) {
	if (msg.handle == m_local_hdl || m_decrypting == 0) {
		m_self->quit(exit_reason::user_shutdown);
	}
}

void gate_state::handle_encrypted_data(const std::vector<char>& buf) {
	if (m_self->valid(m_remote_hdl)) {
		m_self->write(m_remote_hdl, buf.size(), buf.data());
		m_self->flush(m_remote_hdl);
	}
}

void gate_state::handle_decrypted_data(const std::vector<char>& buf) {
	m_self->write(m_local_hdl, buf.size(), buf.data());
	m_self->flush(m_local_hdl);

	if (--m_decrypting == 0 && !m_self->valid(m_remote_hdl)) {
		m_self->quit(exit_reason::user_shutdown);
	}
}

void gate_state::handle_connect_succ(connection_handle hdl) {
	m_self->assign_tcp_scribe(hdl);
	m_remote_hdl = hdl;
	m_self->configure_read(m_remote_hdl, receive_policy::at_most(BUFFER_SIZE));

	if (m_key.empty()) {
		if (m_zlib) {
			m_encryptor = m_self->spawn<linked>(zlib_encryptor_impl, m_encryptor);
		}

		if (!m_buf.empty()) {
			if (m_encryptor) {
				m_self->send(m_encryptor, encrypt_atom::value, std::move(m_buf));
			} else {
				auto& wr_buf = m_self->wr_buf(m_remote_hdl);
				if (wr_buf.empty()) {
					wr_buf = std::move(m_buf);
				} else {
					wr_buf.insert(wr_buf.end(), m_buf.begin(), m_buf.end());
					m_buf.clear();
				}
				m_self->flush(m_remote_hdl);
			}
		}
	} else {
		m_unpacker.expect(4, [this] (std::vector<char> buf) {
			auto seed = *reinterpret_cast<uint32_t*>(buf.data());
			std::minstd_rand rd(seed);
			std::vector<uint8_t> ivec(128 / 8);
			auto data = reinterpret_cast<uint32_t*>(ivec.data());
			for (auto i = 0; i < 4; ++i) {
				data[i] = rd();
			}
			m_encryptor = m_self->spawn<linked>(aes_cfb128_encryptor_impl, m_key, ivec);

			if (m_zlib) {
				m_encryptor = m_self->spawn<linked>(zlib_encryptor_impl, m_encryptor);
			}

			if (!m_buf.empty()) {
				m_self->send(m_encryptor, encrypt_atom::value, std::move(m_buf));
			}

			return true;
		});
	}
}

void gate_state::handle_connect_fail(const std::string& what) {
	log(m_self) << "ERROR: " << what << std::endl;
	m_self->quit(exit_reason::user_shutdown);
}

gate_session::behavior_type
gate_session_impl(	gate_session::stateful_broker_pointer<gate_state> self,
					connection_handle hdl, const std::string& host, uint16_t port,
					const std::vector<uint8_t>& key, bool zlib, int timeout) {
	self->state.init(hdl, host, port, key, zlib);
	return {
		[self] (const new_data_msg& msg) {
			self->state.handle_new_data(msg);
		},
		[self] (const connection_closed_msg& msg) {
			self->state.handle_conn_closed(msg);
		},
		[self] (ok_atom, connection_handle hdl) {
			self->state.handle_connect_succ(hdl);
		},
		[self] (error_atom, const std::string& what) {
			self->state.handle_connect_fail(what);
		},
		[self] (encrypt_atom, const std::vector<char>& buf) {
			self->state.handle_encrypted_data(buf);
		},
		[self] (decrypt_atom, const std::vector<char>& buf) {
			self->state.handle_decrypted_data(buf);
		},
		after(std::chrono::seconds(timeout)) >> [self] {
			self->quit(exit_reason::user_shutdown);
		}
	};
}

} }
