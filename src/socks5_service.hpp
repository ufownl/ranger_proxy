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

#ifndef RANGER_PROXY_SOCKS5_SERVICE_HPP
#define RANGER_PROXY_SOCKS5_SERVICE_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include "user_table.hpp"
#include "encryptor.hpp"

namespace ranger { namespace proxy {

using socks5_service =
  accept_handler::extend<
    replies_to<publish_atom, uint16_t, std::vector<uint8_t>, bool>::with<uint16_t>,
    replies_to<publish_atom, std::string, uint16_t, std::vector<uint8_t>, bool>::with<uint16_t>,
    replies_to<add_atom, std::string, std::string>::with<bool, std::string>
  >;

class socks5_service_state {
public:
  using doorman_info = std::pair<std::vector<uint8_t>, bool>;

  socks5_service_state() = default;

  socks5_service_state(const socks5_service_state&) = delete;
  socks5_service_state& operator = (const socks5_service_state&) = delete;

  void set_user_table(const user_table& tbl);
  const user_table& get_user_table() const;

  void add_doorman_info(accept_handle hdl,
                        const std::vector<uint8_t>& key,
                        bool zlib);
  doorman_info get_doorman_info(accept_handle hdl) const;

  size_t session_count = 0;

private:
  user_table m_user_tbl = unsafe_actor_handle_init;
  std::unordered_map<accept_handle, doorman_info> m_info_map;
};

socks5_service::behavior_type
socks5_service_impl(socks5_service::stateful_broker_pointer<socks5_service_state> self,
                    size_t timeout, bool verbose, const std::string& log);

} }

#endif  // RANGER_PROXY_SOCKS5_SERVICE_HPP
