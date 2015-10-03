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

#ifndef RANGER_PROXY_ASYNC_CONNECT_HPP
#define RANGER_PROXY_ASYNC_CONNECT_HPP

#include "logger_ostream.hpp"
#include <caf/io/network/asio_multiplexer.hpp>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace ranger { namespace proxy {

template <class T>
void async_connect(T self, const in_addr& addr, uint16_t port) {
	using boost::asio::ip::tcp;
	using boost::asio::ip::address_v4;
	tcp::endpoint ep(address_v4(ntohl(addr.s_addr)), port);
	auto fd =
		std::make_shared<network::default_socket>(*self->parent().backend().pimpl());
	using boost::system::error_code;
	fd->async_connect(ep,
		[self, addr, port, fd] (const error_code& ec) {
			if (ec) {
				log(self) << "ERROR: " << ec.message() << std::endl;
				self->send(	self, error_atom::value,
							"could not connect to host: " +
							std::string(inet_ntoa(addr)) +
							":" +std::to_string(port));
			} else {
				auto hdl =
					static_cast<network::asio_multiplexer&>(self->parent().backend())
						.add_tcp_scribe(self, std::move(*fd));
				self->send(self, ok_atom::value, hdl);
			}
		}
	);
}

template <class T>
void async_connect(T self, const std::string& host, uint16_t port) {
	using boost::asio::ip::tcp;
	auto r = std::make_shared<tcp::resolver>(*self->parent().backend().pimpl());
	tcp::resolver::query q(host, std::to_string(port));
	using boost::system::error_code;
	r->async_resolve(q,
		[self, host, port, r] (const error_code& ec, tcp::resolver::iterator it) {
			if (ec) {
				log(self) << "ERROR: " << ec.message() << std::endl;
				self->send(self, error_atom::value, "could not resolve host: " + host);
			} else {
				auto fd = std::make_shared<network::default_socket>(*self->parent().backend().pimpl());
				boost::asio::async_connect(*fd, it,
					[self, host, port, fd] (const error_code& ec, tcp::resolver::iterator it) {
						if (ec) {
							log(self) << "ERROR: " << ec.message() << std::endl;
							self->send(	self, error_atom::value,
										"could not connect to host: " +
										host + ":" + std::to_string(port));
						} else {
							auto hdl =
								static_cast<network::asio_multiplexer&>(self->parent().backend())
									.add_tcp_scribe(self, std::move(*fd));
							self->send(self, ok_atom::value, hdl);
						}
					}
				);
			}
		}
	);
}

} }

#endif	// RANGER_PROXY_ASYNC_CONNECT_HPP
