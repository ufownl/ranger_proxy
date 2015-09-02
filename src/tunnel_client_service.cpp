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
#include "experimental/tunnel_client_service.hpp"

namespace ranger { namespace proxy { namespace experimental {

tunnel_client_state::tunnel_client_state(tunnel_client_service::broker_pointer self)
	: m_self(self) {
	// nop
}

void tunnel_client_state::init(connection_handle hdl) {
	m_remote_hdl = hdl;
	m_self->configure_read(m_remote_hdl, receive_policy::exactly(sizeof(int64_t) + sizeof(uint16_t)));
}

void tunnel_client_state::handle_new_data(const new_data_msg& msg) {
	if (msg.handle == m_remote_hdl) {
		if (m_local_hdl.invalid()) {
			int64_t id;
			uint16_t len;
			memcpy(&id, msg.buf.data(), sizeof(id));
			memcpy(&len, msg.buf.data() + sizeof(id), sizeof(len));

			if (len > 0) {
				m_local_hdl.set_id(id);
				m_self->configure_read(m_remote_hdl, receive_policy::exactly(len));
			} else {
				try {
					m_self->close(connection_handle::from_int(id));
				} catch (const std::invalid_argument& e) {
					aout(m_self) << "WARN: " << e.what() << std::endl;
				}
			}
		} else {
			try {
				m_self->write(m_local_hdl, msg.buf.size(), msg.buf.data());
				m_self->flush(m_local_hdl);
			} catch (const std::invalid_argument& e) {
				aout(m_self) << "WARN: " << e.what() << std::endl;
			}

			m_local_hdl.set_invalid();
			m_self->configure_read(m_remote_hdl, receive_policy::exactly(sizeof(int64_t) + sizeof(uint16_t)));
		}
	} else {
		int64_t id = msg.handle.id();
		uint16_t len = msg.buf.size();
		m_self->write(m_remote_hdl, sizeof(id), &id);
		m_self->write(m_remote_hdl, sizeof(len), &len);
		m_self->write(m_remote_hdl, len, msg.buf.data());
		m_self->flush(m_remote_hdl);
	}
}

void tunnel_client_state::handle_new_conn(const new_connection_msg& msg) {
	m_self->configure_read(msg.handle, receive_policy::at_most(8192));
}

void tunnel_client_state::handle_conn_closed(const connection_closed_msg& msg) {
	if (msg.handle == m_remote_hdl) {
		m_self->quit();
	} else {
		int64_t id = msg.handle.id();
		uint16_t len = 0;
		m_self->write(m_remote_hdl, sizeof(id), &id);
		m_self->write(m_remote_hdl, sizeof(len), &len);
		m_self->flush(m_remote_hdl);
	}
}

tunnel_client_service::behavior_type
tunnel_client_service_impl(tunnel_client_service::stateful_broker_pointer<tunnel_client_state> self, connection_handle hdl) {
	self->state.init(hdl);
	return {
		[self] (const new_connection_msg& msg) {
			self->state.handle_new_conn(msg);
		},
		[self] (const new_data_msg& msg) {
			self->state.handle_new_data(msg);
		},
		[self] (const connection_closed_msg& msg) {
			self->state.handle_conn_closed(msg);
		},
		[] (const acceptor_closed_msg&) {},
		[self] (publish_atom)
			-> either<ok_atom, uint16_t>::or_else<error_atom, std::string> {
			try {
				return {
					ok_atom::value,
					self->add_tcp_doorman(0, "127.0.0.1", true).second
				};
			} catch (const network_error& e) {
				return {error_atom::value, e.what()};
			}
		}
	};
}

} } }
