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
#include "socks5_session.hpp"
#include "connect_helper.hpp"
#include "logger_ostream.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <string.h>

namespace ranger { namespace proxy {

socks5_state::socks5_state(socks5_session::broker_pointer self)
	: m_self(self) {
	// nop
}

socks5_state::~socks5_state() {
	if (m_encryptor) {
		anon_send_exit(m_encryptor, exit_reason::user_shutdown);
	}
}

void socks5_state::init(connection_handle hdl,
						const user_table& tbl,
						const encryptor& enc,
						bool verbose) {
	m_local_hdl = hdl;
	m_self->configure_read(m_local_hdl, receive_policy::at_most(BUFFER_SIZE));
	m_user_tbl = tbl;
	m_encryptor = enc;
	m_verbose = verbose;
	m_valid = true;
	m_unpacker.expect(2, [this] (std::vector<char> buf) {
		return handle_select_method(std::move(buf));
	});
}

void socks5_state::handle_new_data(const new_data_msg& msg) {
	if (!m_valid) {
		log(m_self) << "ERROR: Current state is invalid" << std::endl;
		m_self->quit();
	} else if (m_encryptor) {
		if (msg.handle == m_local_hdl) {
			m_self->send(m_encryptor, decrypt_atom::value, msg.buf);
		} else {
			m_self->send(m_encryptor, encrypt_atom::value, msg.buf);
		}
	} else {
		if (msg.handle == m_local_hdl) {
			if (m_remote_hdl.invalid()) {
				m_unpacker.append(msg.buf);
			} else if (m_self->valid(m_remote_hdl)) {
				write_raw(m_remote_hdl, msg.buf);
			}
		} else {
			write_raw(m_local_hdl, msg.buf);
		}
	}
}

void socks5_state::handle_conn_closed(const connection_closed_msg& msg) {
	if (msg.handle == m_local_hdl) {
		m_self->quit();
	} else {
		m_self->delayed_send(m_self, std::chrono::seconds(2), close_atom::value);
	}
}

void socks5_state::handle_connect_succ(connection_handle hdl) {
	if (m_conn_succ_handler) {
		m_conn_succ_handler(hdl);
	}
}

void socks5_state::handle_connect_fail(const std::string& what) {
	if (m_conn_fail_handler) {
		m_conn_fail_handler(what);
	}
}

void socks5_state::handle_encrypted_data(const std::vector<char>& buf) {
	write_raw(m_local_hdl, buf);
}

void socks5_state::handle_decrypted_data(const std::vector<char>& buf) {
	if (m_remote_hdl.invalid()) {
		m_unpacker.append(buf);
	} else if (m_self->valid(m_remote_hdl)) {
		write_raw(m_remote_hdl, buf);
	}
}

void socks5_state::handle_auth_result(bool result) {
	if (result) {
		if (m_verbose) {
			log(m_self) << "INFO: Auth successfully" << std::endl;
		}

		write_to_local({0x01, 0x00});
		m_unpacker.expect(4, [this] (std::vector<char> buf) {
			return handle_request_header(std::move(buf));
		});
	} else {
		log(m_self) << "ERROR: Username or password error" << std::endl;
		m_valid = false;
		write_to_local({0x01, static_cast<char>(0xFF)});
	}
}

void socks5_state::write_to_local(std::vector<char> buf) const {
	if (m_encryptor) {
		m_self->send(m_encryptor, encrypt_atom::value, std::move(buf));
	} else {
		write_raw(m_local_hdl, std::move(buf));
	}
}

void socks5_state::write_raw(connection_handle hdl, std::vector<char> buf) const {
	auto& wr_buf = m_self->wr_buf(hdl);
	if (wr_buf.empty()) {
		wr_buf = std::move(buf);
	} else {
		wr_buf.insert(wr_buf.end(), buf.begin(), buf.end());
	}
	m_self->flush(hdl);

	if (!m_valid) {
		m_self->delayed_send(m_self, std::chrono::seconds(2), close_atom::value);
	}
}

bool socks5_state::handle_select_method(std::vector<char> buf) {
	if (static_cast<uint8_t>(buf[0]) != 0x05) {
		log(m_self) << "ERROR: Protocol version mismatch" << std::endl;
		m_self->quit();
		return false;
	}

	uint8_t nmethods = buf[1];
	if (nmethods == 0) {
		log(m_self) << "ERROR: NO ACCEPTABLE METHODS" << std::endl;
		m_valid = false;
		write_to_local({0x05, static_cast<char>(0xFF)});
		return false;
	}

	if (m_verbose) {
		log(m_self) << "INFO: recv select method header"
			<< " (nmethods == " << nmethods << ")" << std::endl;
	}

	m_unpacker.expect(nmethods, [this] (std::vector<char> buf) {
		if (m_verbose) {
			log(m_self) << "INFO: recv select method data" << std::endl;
			for (auto i = 0; i < buf.size(); ++i) {
				log(m_self) << "INFO: method[" << i << "] = "
					<< static_cast<unsigned int>(buf[i]) << std::endl;
			}
		}

		uint8_t method = 0x00;
		if (m_user_tbl) {
			method = 0x02;
		}

		if (std::find(buf.begin(), buf.end(), method) != buf.end()) {
			write_to_local({0x05, static_cast<char>(method)});
			if (method == 0x00) {
				if (m_verbose) {
					log(m_self) << "INFO: Select method [NO AUTHENTICATION REQUIRED]" << std::endl;
				}
				m_unpacker.expect(4, [this] (std::vector<char> buf) {
					return handle_request_header(std::move(buf));
				});
			} else {
				if (m_verbose) {
					log(m_self) << "INFO: Select method [USERNAME/PASSWORD]" << std::endl;
				}
				m_unpacker.expect(2, [this] (std::vector<char> buf) {
					return handle_username_auth(std::move(buf));
				});
			}
		} else {
			log(m_self) << "ERROR: NO ACCEPTABLE METHODS" << std::endl;
			m_valid = false;
			write_to_local({0x05, static_cast<char>(0xFF)});
			return false;
		}

		return true;
	});

	return true;
}

bool socks5_state::handle_username_auth(std::vector<char> buf) {
	if (static_cast<uint8_t>(buf[0]) != 0x01) {
		log(m_self) << "ERROR: Protocol version mismatch" << std::endl;
		m_self->quit();
		return false;
	}

	uint8_t len = buf[1];
	if (len == 0) {
		log(m_self) << "ERROR: Username is empty" << std::endl;
		m_valid = false;
		write_to_local({0x01, static_cast<char>(0xFF)});
		return false;
	}

	m_unpacker.expect(len + 1, [this] (std::vector<char> buf) {
		uint8_t len = buf.back();
		std::string username(buf.begin(), buf.begin() + buf.size() - 1);
		if (len > 0) {
			m_unpacker.expect(len, [this, username] (std::vector<char> buf) {
				std::string password(buf.begin(), buf.end());
				if (m_verbose) {
					log(m_self) << "INFO: Auth [" << username << " & " << password << "]" << std::endl;
				}

				m_self->send(m_user_tbl, auth_atom::value, username, password);
				return true;
			});
		} else {
			if (m_verbose) {
				log(m_self) << "INFO: Auth [" << username << " & [empty]]" << std::endl;
			}

			m_self->send(m_user_tbl, auth_atom::value, username, std::string());
		}

		return true;
	});

	return true;
}

bool socks5_state::handle_request_header(std::vector<char> buf) {
	if (static_cast<uint8_t>(buf[0]) != 0x05) {
		log(m_self) << "ERROR: Protocol version mismatch" << std::endl;
		m_self->quit();
		return false;
	}

	if (m_verbose) {
		log(m_self) << "INFO: recv request header" << std::endl;
	}

	if (static_cast<uint8_t>(buf[1]) != 0x01) {
		log(m_self) << "ERROR: Command not supported" << std::endl;
		m_valid = false;
		write_to_local({0x05, 0x07, 0x00, 0x01});
		return false;
	}

	switch (static_cast<uint8_t>(buf[3])) {
	case 0x01:	// IPV4
		if (m_verbose) {
			log(m_self) << "INFO: CMD[connect] ADDR[ipv4]" << std::endl;
		}
		m_unpacker.expect(6, [this] (std::vector<char> buf) {
			return handle_ipv4_request(std::move(buf));
		});
		return true;
	case 0x03:	// DOMAINNAME
		if (m_verbose) {
			log(m_self) << "INFO: CMD[connect] ADDR[domainname]" << std::endl;
		}
		m_unpacker.expect(1, [this] (std::vector<char> buf) {
			return handle_domainname_request(std::move(buf));
		});
		return true;
	}

	log(m_self) << "ERROR: Address type not supported" << std::endl;
	m_valid = false;
	write_to_local({0x05, 0x08, 0x00, 0x01});
	return false;
}

bool socks5_state::handle_ipv4_request(std::vector<char> buf) {
	in_addr addr;
	memcpy(&addr, &buf[0], sizeof(addr));
	uint16_t port;
	memcpy(&port, &buf[4], sizeof(port));
	port = ntohs(port);

	if (m_verbose) {
		log(m_self) << "INFO: connect to " << inet_ntoa(addr) << ":" << port << std::endl;
	}

	auto helper = m_self->spawn(connect_helper_impl, &m_self->parent().backend());
	m_self->send(helper, connect_atom::value, inet_ntoa(addr), port);

	m_valid = false;
	port = htons(port);

	m_conn_succ_handler = [this, addr, port] (connection_handle remote_hdl) {
		m_self->assign_tcp_scribe(remote_hdl);
		m_remote_hdl = remote_hdl;
		m_valid = true;

		if (m_verbose) {
			log(m_self) << "INFO: " << inet_ntoa(addr) << ":" << ntohs(port) << " connected" << std::endl;
		}
		
		std::vector<char> buf = {0x05, 0x00, 0x00, 0x01};
		buf.insert(	buf.end(),
					reinterpret_cast<const char*>(&addr),
					reinterpret_cast<const char*>(&addr) + sizeof(addr));
		buf.insert(	buf.end(),
					reinterpret_cast<const char*>(&port),
					reinterpret_cast<const char*>(&port) + sizeof(port));
		write_to_local(std::move(buf));

		m_self->configure_read(m_remote_hdl, receive_policy::at_most(BUFFER_SIZE));
	};

	m_conn_fail_handler = [this, addr, port] (const std::string& what) {
		log(m_self) << "ERROR: " << what << std::endl;
		std::vector<char> buf = {0x05, 0x05, 0x00, 0x01};
		buf.insert(	buf.end(),
					reinterpret_cast<const char*>(&addr),
					reinterpret_cast<const char*>(&addr) + sizeof(addr));
		buf.insert(	buf.end(),
					reinterpret_cast<const char*>(&port),
					reinterpret_cast<const char*>(&port) + sizeof(port));
		write_to_local(std::move(buf));
	};

	return true;
}

bool socks5_state::handle_domainname_request(std::vector<char> buf) {
	m_unpacker.expect(static_cast<uint8_t>(buf[0]) + 2, [this] (std::vector<char> buf) {
		std::string host(buf.begin(), buf.begin() + buf.size() - 2);
		uint16_t port;
		memcpy(&port, &buf[buf.size() - 2], sizeof(port));
		port = ntohs(port);

		if (m_verbose) {
			log(m_self) << "INFO: connect to " << host << ":" << port << std::endl;
		}

		auto helper = m_self->spawn(connect_helper_impl, &m_self->parent().backend());
		m_self->send(helper, connect_atom::value, host, port);

		m_valid = false;
		port = htons(port);

		m_conn_succ_handler = [this, host, port] (connection_handle remote_hdl) {
			m_self->assign_tcp_scribe(remote_hdl);
			m_remote_hdl = remote_hdl;
			m_valid = true;

			if (m_verbose) {
				log(m_self) << "INFO: " << host << ":" << ntohs(port) << " connected" << std::endl;
			}

			std::vector<char> buf = {0x05, 0x00, 0x00, 0x03, static_cast<char>(host.size())};
			buf.insert(	buf.end(), host.begin(), host.end());
			buf.insert(	buf.end(),
						reinterpret_cast<const char*>(&port),
						reinterpret_cast<const char*>(&port) + sizeof(port));
			write_to_local(std::move(buf));

			m_self->configure_read(m_remote_hdl, receive_policy::at_most(BUFFER_SIZE));
		};

		m_conn_fail_handler = [this, host, port] (const std::string& what) {
			log(m_self) << "ERROR: " << what << std::endl;
			std::vector<char> buf = {0x05, 0x05, 0x00, 0x03, static_cast<char>(host.size())};
			buf.insert(	buf.end(), host.begin(), host.end());
			buf.insert(	buf.end(),
						reinterpret_cast<const char*>(&port),
						reinterpret_cast<const char*>(&port) + sizeof(port));
			write_to_local(std::move(buf));
		};

		return true;
	});
	
	return true;
}

socks5_session::behavior_type
socks5_session_impl(socks5_session::stateful_broker_pointer<socks5_state> self,
					connection_handle hdl, user_table tbl, encryptor enc,
					int timeout, bool verbose) {
	self->state.init(hdl, tbl, enc, verbose);
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
		[self] (auth_atom, bool result) {
			self->state.handle_auth_result(result);
		},
		[self] (close_atom) {
			self->quit();
		},
		after(std::chrono::seconds(timeout)) >> [self] {
			self->quit();
		}
	};
}

} }
