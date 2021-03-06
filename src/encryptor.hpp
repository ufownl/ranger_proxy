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

#ifndef RANGER_PROXY_ENCRYPTOR_HPP
#define RANGER_PROXY_ENCRYPTOR_HPP

#include <vector>

namespace ranger { namespace proxy {

using encrypt_atom = atom_constant<atom("encrypt")>;
using decrypt_atom = atom_constant<atom("decrypt")>;

using encryptor = typed_actor<
  replies_to<encrypt_atom, std::vector<char>>::with<encrypt_atom, std::vector<char>>,
  replies_to<decrypt_atom, std::vector<char>>::with<decrypt_atom, std::vector<char>>
>;

} }

#endif  // RANGER_PROXY_ENCRYPTOR_HPP
