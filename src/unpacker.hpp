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

#ifndef RANGER_PROXY_UNPACKER_HPP
#define RANGER_PROXY_UNPACKER_HPP

#include <vector>
#include <queue>
#include "scope_guard.hpp"

namespace ranger { namespace proxy {

template <class SizeType>
class unpacker {
public:
  using size_type = SizeType;

  unpacker() = default;

  unpacker(const unpacker&) = delete;
  unpacker& operator = (const unpacker&) = delete;

  void append(std::vector<char> buf) {
    m_current_len += buf.size();
    m_buffers.emplace(std::move(buf));
    consume();
  }

  template <class T>
  void expect(size_type len, T&& handler) {
    m_expected_len = len;
    m_expected_handler = std::forward<T>(handler);
    consume();
  }

private:
  void consume() {
    if (m_consuming) {
      return;
    }

    m_consuming = true;
    scope_guard consuming_guard([this] { m_consuming = false; });

    while (m_expected_len > 0 && m_current_len - m_offset >= m_expected_len) {
      std::vector<char> expected_buf;
      do {
        if (m_offset + m_expected_len < m_buffers.front().size()) {
          expected_buf.insert(expected_buf.end(),
                              m_buffers.front().begin() + m_offset,
                              m_buffers.front().begin() + m_offset + m_expected_len);
          m_offset += m_expected_len;
          m_expected_len = 0;
        } else {
          expected_buf.insert(expected_buf.end(),
                              m_buffers.front().begin() + m_offset,
                              m_buffers.front().end());
          m_current_len -= m_buffers.front().size();
          m_expected_len -= m_buffers.front().size() - m_offset;
          m_offset = 0;
          m_buffers.pop();
        }
      } while (m_expected_len > 0);

      if (!m_expected_handler(std::move(expected_buf))) {
        break;
      }
    }
  }

  std::queue<std::vector<char>> m_buffers;
  size_t m_current_len {0};
  size_type m_offset {0};
  size_type m_expected_len {0};
  std::function<bool(std::vector<char>)> m_expected_handler;
  bool m_consuming {false};
};

} }

#endif  // RANGER_PROXY_UNPACKER_HPP
