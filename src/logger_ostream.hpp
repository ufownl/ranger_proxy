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

#ifndef RANGER_PROXY_LOGGER_OSTREAM_HPP
#define RANGER_PROXY_LOGGER_OSTREAM_HPP

#include "logger.hpp"

namespace ranger { namespace proxy {

class logger_ostream {
public:
	using func_type = logger_ostream& (*)(logger_ostream&);

	static void redirect(logger lgr);

	explicit logger_ostream(actor self);

	logger_ostream& write(const std::string& content);
	logger_ostream& flush();

	logger_ostream& operator << (const std::string& content);
	logger_ostream& operator << (func_type func);

	template <class T>
	typename std::enable_if<
		!std::is_convertible<T, std::string>::value, logger_ostream&
	>::type operator << (T&& content) {
		using std::to_string;
		using caf::to_string;
		return write(to_string(std::forward<T>(content)));
	}

private:
	static logger m_logger;
	actor m_self;
	std::string m_content;
};

logger_ostream log(const scoped_actor& self);
logger_ostream log(abstract_actor* self);

} }

namespace std {

ranger::proxy::logger_ostream& endl(ranger::proxy::logger_ostream& ostrm);
ranger::proxy::logger_ostream& flush(ranger::proxy::logger_ostream& ostrm);

}

#endif	// RANGER_PROXY_LOGGER_OSTREAM_HPP
