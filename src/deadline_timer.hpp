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

#ifndef RANGER_PROXY_DEADLINE_TIMER_HPP
#define RANGER_PROXY_DEADLINE_TIMER_HPP

namespace ranger { namespace proxy {

using reset_atom = atom_constant<atom("reset")>;

using deadline_timer = typed_actor<reacts_to<reset_atom>>;

deadline_timer::behavior_type
deadline_timer_impl(deadline_timer::pointer self, int timeout);

} }

#endif	// RANGER_PROXY_DEADLINE_TIMER_HPP
