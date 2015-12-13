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

#ifndef RANGER_PROXY_COMMON_HPP
#define RANGER_PROXY_COMMON_HPP

#include <caf/all.hpp>
#include <caf/io/all.hpp>

// experimental headers
#include <caf/io/experimental/typed_broker.hpp>

namespace ranger { namespace proxy {

const size_t BUFFER_SIZE = 256 * 1024;  // default: 256k

using namespace caf;
using namespace caf::io;
using namespace caf::io::experimental;

} }

#endif  // RANGER_PROXY_COMMON_HPP
