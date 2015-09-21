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
#include "logger.hpp"
#include <time.h>

namespace ranger { namespace proxy {

void logger_state::init(const std::string& path) {
	m_fout.reset(new std::ofstream(path));
	m_buf.resize(64);
}

void logger_state::write(const std::string& content) {
	time_t now = time(nullptr);
	while (strftime(m_buf.data(), m_buf.size(), "[%c] ", localtime(&now)) == 0) {
		m_buf.resize(m_buf.size() * 2);
	}

	*m_fout << m_buf.data() << content << std::flush;
}

logger::behavior_type
logger_impl(logger::stateful_pointer<logger_state> self, const std::string& path) {
	self->state.init(path);
	return {
		[self] (const std::string& content) {
			self->state.write(content);
		}
	};
}

} }
