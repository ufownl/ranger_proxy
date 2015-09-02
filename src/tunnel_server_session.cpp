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
#include "experimental/tunnel_server_session.hpp"
#include <string.h>

namespace ranger { namespace proxy { namespace experimental {

tunnel_server_state::tunnel_server_state(tunnel_server_session::broker_pointer self)
	: m_self(self) {
	// nop
}

void tunnel_server_state::init(connection_handle hdl, const std::string& host, uint16_t port) {
	m_local_hdl = hdl;
	m_self->configure_read(m_local_hdl, receive_policy::exactly(sizeof(int64_t) + sizeof(uint16_t)));

	m_host = host;
	m_port = port;
}

void tunnel_server_state::handle_new_data(const new_data_msg& msg) {
	if (msg.handle == m_local_hdl) {
		if (m_remote_hdl.invalid()) {
			int64_t id;
			uint16_t len;
			memcpy(&id, msg.buf.data(), sizeof(id));
			memcpy(&len, msg.buf.data() + sizeof(id), sizeof(len));

			auto it = m_id_to_hdl.find(id);
			if (it == m_id_to_hdl.end()) {
				if (3 <= len && len <= 257) {
					try {
						m_remote_hdl = m_self->add_tcp_scribe(m_host, m_port);
						m_self->configure_read(m_remote_hdl, receive_policy::at_most(8192));

						m_id_to_hdl.emplace(id, m_remote_hdl);
						m_hdl_to_id.emplace(m_remote_hdl, id);

						m_self->configure_read(m_local_hdl, receive_policy::exactly(len));
					} catch (const network_error& e) {
						aout(m_self) << "ERROR: " << e.what() << std::endl;
					}
				} else if (len > 0) {
					aout(m_self) << "ERROR: Tunnel protocol error" << std::endl;
					m_self->quit();
				}
			} else if (len > 0) {
				m_remote_hdl = it->second;
				m_self->configure_read(m_local_hdl, receive_policy::exactly(len));
			} else {
				m_self->close(it->second);
				m_hdl_to_id.erase(it->second);
				m_id_to_hdl.erase(it);
			}
		} else {
			m_self->write(m_remote_hdl, msg.buf.size(), msg.buf.data());
			m_self->flush(m_remote_hdl);

			m_remote_hdl.set_invalid();
			m_self->configure_read(m_local_hdl, receive_policy::exactly(sizeof(int64_t) + sizeof(uint16_t)));
		}
	} else {
		auto it = m_hdl_to_id.find(msg.handle);
		if (it != m_hdl_to_id.end()) {
			int64_t id = it->second;
			uint16_t len = msg.buf.size();
			m_self->write(m_local_hdl, sizeof(id), &id);
			m_self->write(m_local_hdl, sizeof(len), &len);
			m_self->write(m_local_hdl, len, msg.buf.data());
			m_self->flush(m_local_hdl);
		}
	}
}

void tunnel_server_state::handle_conn_closed(const connection_closed_msg& msg) {
	if (msg.handle == m_local_hdl) {
		m_self->quit();
	} else {
		auto it = m_hdl_to_id.find(msg.handle);
		if (it != m_hdl_to_id.end()) {
			int64_t id = it->second;
			uint16_t len = 0;
			m_self->write(m_local_hdl, sizeof(id), &id);
			m_self->write(m_local_hdl, sizeof(len), &len);
			m_self->flush(m_local_hdl);
			
			m_id_to_hdl.erase(it->second);
			m_hdl_to_id.erase(it);
		}
	}
}

tunnel_server_session::behavior_type
tunnel_server_session_impl(	tunnel_server_session::stateful_broker_pointer<tunnel_server_state> self,
							connection_handle hdl, const std::string& host, uint16_t port) {
	self->state.init(hdl, host, port);
	return {
		[self] (const new_data_msg& msg) {
			self->state.handle_new_data(msg);
		},
		[self] (const connection_closed_msg& msg) {
			self->state.handle_conn_closed(msg);
		},
	};
}

} } }
