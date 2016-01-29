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

#ifndef RANGER_PROXY_SCOPE_GUARD_HPP
#define RANGER_PROXY_SCOPE_GUARD_HPP

#include <utility>

namespace ranger { namespace proxy {

template <class T>
class scope_guard {
public:
  explicit scope_guard(T handler)
    : m_exit_handler(std::move(handler))
    , m_dismiss(false) {
    // nop
  }

  ~scope_guard() {
    if (!m_dismiss) {
      m_exit_handler();
    }
  }

  scope_guard(const scope_guard&) = delete;
  scope_guard& operator = (const scope_guard&) = delete;

  scope_guard(scope_guard<T>&& rhs)
    : m_exit_handler(std::move(rhs.m_exit_handler))
    , m_dismiss(rhs.m_dismiss) {
    rhs.m_dismiss = false;
  }

  void dismiss() {
    m_dismiss = true;
  }

private:
  T m_exit_handler;
  bool m_dismiss;
};

template <class T>
scope_guard<T> make_scope_guard(T handler) {
  return scope_guard<T>(std::move(handler));
}

} }

#endif  // RANGER_PROXY_SCOPE_GUARD_HPP
