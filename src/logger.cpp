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
	m_fout = std::ofstream(path);
}

void logger_state::write(const std::string& content) {
	time_t now = time(nullptr);
	const tm* now_tm = localtime(&now);
	m_fout << std::put_time(now_tm, "[%c] ") << content << std::flush;
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
