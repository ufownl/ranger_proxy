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

#include "test_util.hpp"
#include "tunnel_server_service.cpp"
#include "tunnel_server_session.cpp"
#include "tunnel_client_service.cpp"
#include "aes_cfb128_encryptor.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <chrono>

TEST_F(echo_test, tunnel_echo) {
	auto tunnel_server =
		caf::io::spawn_io(	ranger::proxy::experimental::tunnel_server_service_impl,
							"127.0.0.1", m_port);
	scope_guard guard_tunnel_server([tunnel_server] {
		caf::anon_send_exit(tunnel_server, caf::exit_reason::kill);
	});

	uint16_t port = 0;
	{
		caf::scoped_actor self;
		self->sync_send(tunnel_server, caf::publish_atom::value, static_cast<uint16_t>(0)).await(
			[&port] (caf::ok_atom, uint16_t tunnel_port) {
				port = tunnel_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	auto tunnel_client =
		caf::io::spawn_io_client(	ranger::proxy::experimental::tunnel_client_service_impl,
									"127.0.0.1", port);
	scope_guard guard_tunnel_client([tunnel_client] {
		caf::anon_send_exit(tunnel_client, caf::exit_reason::kill);
	});
	{
		caf::scoped_actor self;
		self->sync_send(tunnel_client, caf::publish_atom::value).await(
			[&port] (caf::ok_atom, uint16_t tunnel_port) {
				port = tunnel_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_NE(-1, fd);
	scope_guard guard_fd([fd] { close(fd); });

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(port);
	ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

	char buf[] = "Hello, world!";
	send(fd, buf, sizeof(buf), 0);
	memset(buf, 0, sizeof(buf));
	ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
	EXPECT_STREQ("Hello, world!", buf);
}

TEST_F(echo_test, tunnel_echo_chain) {
	auto tunnel_server =
		caf::io::spawn_io(	ranger::proxy::experimental::tunnel_server_service_impl,
							"127.0.0.1", m_port);
	scope_guard guard_tunnel_server([tunnel_server] {
		caf::anon_send_exit(tunnel_server, caf::exit_reason::kill);
	});

	uint16_t port = 0;
	{
		caf::scoped_actor self;
		self->sync_send(tunnel_server, caf::publish_atom::value, static_cast<uint16_t>(0)).await(
			[&port] (caf::ok_atom, uint16_t tunnel_port) {
				port = tunnel_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	auto tunnel_client =
		caf::io::spawn_io_client(	ranger::proxy::experimental::tunnel_client_service_impl,
									"127.0.0.1", port);
	scope_guard guard_tunnel_client([tunnel_client] {
		caf::anon_send_exit(tunnel_client, caf::exit_reason::kill);
	});
	{
		caf::scoped_actor self;
		self->sync_send(tunnel_client, caf::publish_atom::value).await(
			[&port] (caf::ok_atom, uint16_t tunnel_port) {
				port = tunnel_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	auto tunnel_server2 =
		caf::io::spawn_io(	ranger::proxy::experimental::tunnel_server_service_impl,
							"127.0.0.1", port);
	scope_guard guard_tunnel_server2([tunnel_server2] {
		caf::anon_send_exit(tunnel_server2, caf::exit_reason::kill);
	});
	{
		caf::scoped_actor self;
		self->sync_send(tunnel_server2, caf::publish_atom::value, static_cast<uint16_t>(0)).await(
			[&port] (caf::ok_atom, uint16_t tunnel_port) {
				port = tunnel_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	auto tunnel_client2 =
		caf::io::spawn_io_client(	ranger::proxy::experimental::tunnel_client_service_impl,
									"127.0.0.1", port);
	scope_guard guard_tunnel_client2([tunnel_client2] {
		caf::anon_send_exit(tunnel_client2, caf::exit_reason::kill);
	});
	{
		caf::scoped_actor self;
		self->sync_send(tunnel_client2, caf::publish_atom::value).await(
			[&port] (caf::ok_atom, uint16_t tunnel_port) {
				port = tunnel_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_NE(-1, fd);
	scope_guard guard_fd([fd] { close(fd); });

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(port);
	ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

	char buf[] = "Hello, world!";
	send(fd, buf, sizeof(buf), 0);
	memset(buf, 0, sizeof(buf));
	ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
	EXPECT_STREQ("Hello, world!", buf);
}
