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

#ifndef RANGER_PROXY_LOGGER_HPP
#define RANGER_PROXY_LOGGER_HPP

#include <string>
#include <fstream>

namespace ranger { namespace proxy {

using logger = typed_actor<reacts_to<std::string>>;

class logger_state {
public:
	logger_state() = default;

	logger_state(const logger_state&) = delete;
	logger_state& operator = (const logger_state&) = delete;

	void init(const std::string& path);
	void write(const std::string& content);

private:
	std::ofstream m_fout;
};

logger::behavior_type
logger_impl(logger::stateful_pointer<logger_state> self, const std::string& path);

} }

#endif	// RANGER_PROXY_LOGGER_HPP
