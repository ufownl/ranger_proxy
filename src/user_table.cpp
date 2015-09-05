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
#include "user_table.hpp"
#include <unordered_map>
#include <memory>

namespace ranger { namespace proxy {

user_table::behavior_type user_table_impl(user_table::pointer self) {
	auto tbl = std::make_shared<std::unordered_map<std::string, std::string>>();
	return {
		[=] (add_atom, const std::string& username, const std::string& password) {
			return std::make_tuple(tbl->emplace(username, password).second, username);
		},
		[=] (auth_atom, const std::string& username, const std::string& password) {
			auto it = tbl->find(username);
			if (it == tbl->end()) {
				return false;
			}

			if (it->second != password) {
				return false;
			}

			return true;
		}
	};
}

} }
