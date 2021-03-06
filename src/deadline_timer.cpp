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
#include "deadline_timer.hpp"

namespace ranger { namespace proxy {

deadline_timer::behavior_type
deadline_timer_impl(deadline_timer::pointer self, int timeout) {
  return {
    [] (reset_atom) {
      // nop
    },
    after(std::chrono::seconds(timeout)) >> [self] {
      self->quit(exit_reason::user_shutdown);
    }
  };
}

} }
