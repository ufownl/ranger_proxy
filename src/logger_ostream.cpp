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
#include "logger_ostream.hpp"

namespace ranger { namespace proxy {

logger logger_ostream::m_logger;

void logger_ostream::redirect(logger lgr) {
	m_logger = lgr;
}

logger_ostream::logger_ostream(actor self)
	: m_self(self) {
	// nop
}

logger_ostream& logger_ostream::write(const std::string& content) {
	m_content += content;
	return *this;
}

logger_ostream& logger_ostream::flush() {
	if (m_logger) {
		send_as(m_self, m_logger, std::move(m_content));
	} else {
		aout(m_self) << std::move(m_content) << std::flush;
	}
	return *this;
}

logger_ostream& logger_ostream::operator << (const std::string& content) {
	return write(content);
}

logger_ostream& logger_ostream::operator << (func_type func) {
	return func(*this);
}

logger_ostream log(actor self) {
	return logger_ostream(self);
}

} }

namespace std {

ranger::proxy::logger_ostream& endl(ranger::proxy::logger_ostream& ostrm) {
	return ostrm.write("\n").flush();
}

ranger::proxy::logger_ostream& flush(ranger::proxy::logger_ostream& ostrm) {
	return ostrm.flush();
}

}
