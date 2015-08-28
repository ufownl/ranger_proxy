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
#include "connect_helper.hpp"

namespace ranger { namespace proxy {

gate_state::gate_state(gate_session::broker_pointer self)
	: m_self(self) {
	// nop
}

void gate_state::init(connection_handle hdl, const std::string& host, uint16_t port) {
	m_local_hdl = hdl;

	auto helper = m_self->spawn<linked>(connect_helper_impl, &m_self->parent().backend());
	m_self->send(helper, connect_atom::value, host, port);
}

void gate_state::handle_new_data(const new_data_msg& msg) {
	if (msg.handle == m_local_hdl) {
		m_self->write(m_remote_hdl, msg.buf.size(), msg.buf.data());
		m_self->flush(m_remote_hdl);
	} else {
		m_self->write(m_local_hdl, msg.buf.size(), msg.buf.data());
		m_self->flush(m_local_hdl);
	}
}

void gate_state::handle_connect_succ(connection_handle hdl) {
	m_self->assign_tcp_scribe(hdl);
	m_remote_hdl = hdl;

	m_self->configure_read(m_local_hdl, receive_policy::at_most(8192));
	m_self->configure_read(m_remote_hdl, receive_policy::at_most(8192));
}

void gate_state::handle_connect_fail(const std::string& what) {
	aout(m_self) << "ERROR: " << what << std::endl;
	m_self->quit();
}

gate_session::behavior_type
gate_session_impl(	gate_session::stateful_broker_pointer<gate_state> self,
					connection_handle hdl, const std::string& host, uint16_t port) {
	self->state.init(hdl, host, port);
	return {
		[self] (const new_data_msg& msg) {
			self->state.handle_new_data(msg);
		},
		[self] (const connection_closed_msg&) {
			self->quit();
		},
		[self] (ok_atom, connection_handle hdl) {
			self->state.handle_connect_succ(hdl);
		},
		[self] (error_atom, const std::string& what) {
			self->state.handle_connect_fail(what);
		}
	};
}

} }
