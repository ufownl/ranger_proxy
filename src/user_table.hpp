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

#ifndef RANGER_PROXY_USER_TABLE_HPP
#define RANGER_PROXY_USER_TABLE_HPP

#include <string>

namespace ranger { namespace proxy {

using auth_atom = atom_constant<atom("auth")>;

using user_table = typed_actor<
	replies_to<add_atom, std::string, std::string>::with<bool, std::string>,
	replies_to<auth_atom, std::string, std::string>::with<auth_atom, bool>
>;

user_table::behavior_type user_table_impl(user_table::pointer self);

} }

#endif	// RANGER_PROXY_USER_TABLE_HPP
