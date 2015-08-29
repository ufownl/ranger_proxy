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
#include "socks5_service.cpp"
#include "socks5_session.cpp"
#include "connect_helper.cpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

TEST_F(echo_test, socks5_no_auth_conn_ipv4) {
	auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl);
	scope_guard guard_socks5([socks5] {
		caf::anon_send_exit(socks5, caf::exit_reason::kill);
	});

	uint16_t port = 0;
	{
		caf::scoped_actor self;
		self->sync_send(socks5, caf::publish_atom::value, port).await(
			[&port] (caf::ok_atom, uint16_t socks5_port) {
				port = socks5_port;
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

	{
		// version identifier/method selection message
		uint8_t buf[] = {0x05, 0x01, 0x00};
		send(fd, buf, sizeof(buf), 0);
	}

	{
		// method selection message
		uint8_t buf[2];
		ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
		ASSERT_EQ(0x05, buf[0]);
		ASSERT_EQ(0x00, buf[1]);
	}

	{
		// request
		uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
		send(fd, buf, sizeof(buf), 0);
		send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0);
		uint16_t remote_port = htons(m_port);
		send(fd, &remote_port, sizeof(remote_port), 0);
	}

	{
		// reply
		uint8_t buf[4];
		ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
		ASSERT_EQ(0x05, buf[0]);
		ASSERT_EQ(0x00, buf[1]);
		ASSERT_EQ(0x00, buf[2]);
		ASSERT_EQ(0x01, buf[3]);
		uint32_t remote_addr;
		ASSERT_EQ(sizeof(remote_addr), recv(fd, &remote_addr, sizeof(remote_addr), 0));
		ASSERT_EQ(sin.sin_addr.s_addr, remote_addr);
		uint16_t remote_port;
		ASSERT_EQ(sizeof(remote_port), recv(fd, &remote_port, sizeof(remote_port), 0));
		ASSERT_EQ(htons(m_port), remote_port);
	}

	{
		// test data
		char buf[] = "Hello, world!";
		send(fd, buf, sizeof(buf), 0);
		memset(buf, 0, sizeof(buf));
		ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
		EXPECT_STREQ("Hello, world!", buf);
	}
}

TEST_F(echo_test, socks5_no_auth_conn_domainname) {
	auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl);
	scope_guard guard_socks5([socks5] {
		caf::anon_send_exit(socks5, caf::exit_reason::kill);
	});

	uint16_t port = 0;
	{
		caf::scoped_actor self;
		self->sync_send(socks5, caf::publish_atom::value, port).await(
			[&port] (caf::ok_atom, uint16_t socks5_port) {
				port = socks5_port;
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

	{
		// version identifier/method selection message
		uint8_t buf[] = {0x05, 0x01, 0x00};
		send(fd, buf, sizeof(buf), 0);
	}

	{
		// method selection message
		uint8_t buf[2];
		ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
		ASSERT_EQ(0x05, buf[0]);
		ASSERT_EQ(0x00, buf[1]);
	}

	{
		// request
		uint8_t buf[] = {0x05, 0x01, 0x00, 0x03};
		send(fd, buf, sizeof(buf), 0);
		char ip[] = "127.0.0.1";
		uint8_t len = sizeof(ip) - 1;
		send(fd, &len, sizeof(len), 0);
		send(fd, ip, len, 0);
		uint16_t remote_port = htons(m_port);
		send(fd, &remote_port, sizeof(remote_port), 0);
	}

	{
		// reply
		uint8_t buf[4];
		ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
		ASSERT_EQ(0x05, buf[0]);
		ASSERT_EQ(0x00, buf[1]);
		ASSERT_EQ(0x00, buf[2]);
		ASSERT_EQ(0x03, buf[3]);
		uint8_t len;
		ASSERT_EQ(sizeof(len), recv(fd, &len, sizeof(len), 0));
		char ip[sizeof("127.0.0.1")];
		ASSERT_EQ(len, recv(fd, ip, len, 0));
		ASSERT_STREQ("127.0.0.1", ip);
		uint16_t remote_port;
		ASSERT_EQ(sizeof(remote_port), recv(fd, &remote_port, sizeof(remote_port), 0));
		ASSERT_EQ(htons(m_port), remote_port);
	}

	{
		// test data
		char buf[] = "Hello, world!";
		send(fd, buf, sizeof(buf), 0);
		ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
		EXPECT_STREQ("Hello, world!", buf);
	}
}

TEST_F(ranger_proxy_test, socks5_no_auth_conn_ipv4_null) {
	auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl);
	scope_guard guard_socks5([socks5] {
		caf::anon_send_exit(socks5, caf::exit_reason::kill);
	});

	uint16_t port = 0;
	{
		caf::scoped_actor self;
		self->sync_send(socks5, caf::publish_atom::value, port).await(
			[&port] (caf::ok_atom, uint16_t socks5_port) {
				port = socks5_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	for (auto i = 0; i < 10; ++i) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_NE(-1, fd);
		scope_guard guard_fd([fd] { close(fd); });

		sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");
		sin.sin_port = htons(port);
		ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

		{
			// version identifier/method selection message
			uint8_t buf[] = {0x05, 0x01, 0x00};
			send(fd, buf, sizeof(buf), 0);
		}

		{
			// method selection message
			uint8_t buf[2];
			ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
			ASSERT_EQ(0x05, buf[0]);
			ASSERT_EQ(0x00, buf[1]);
		}

		{
			// request
			uint8_t buf[] = {0x05, 0x01, 0x00, 0x01};
			send(fd, buf, sizeof(buf), 0);
			send(fd, &sin.sin_addr, sizeof(sin.sin_addr), 0);
			uint16_t remote_port = htons(0);
			send(fd, &remote_port, sizeof(remote_port), 0);
		}

		{
			// reply
			uint8_t buf[4];
			ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
			EXPECT_EQ(0x05, buf[0]);
			EXPECT_EQ(0x05, buf[1]);
			EXPECT_EQ(0x00, buf[2]);
			EXPECT_EQ(0x01, buf[3]);
			uint32_t remote_addr;
			ASSERT_EQ(sizeof(remote_addr), recv(fd, &remote_addr, sizeof(remote_addr), 0));
			EXPECT_EQ(sin.sin_addr.s_addr, remote_addr);
			uint16_t remote_port;
			ASSERT_EQ(sizeof(remote_port), recv(fd, &remote_port, sizeof(remote_port), 0));
			EXPECT_EQ(htons(0), remote_port);
		}
	}
}

TEST_F(ranger_proxy_test, socks5_no_auth_conn_domainname_null) {
	auto socks5 = caf::io::spawn_io(ranger::proxy::socks5_service_impl);
	scope_guard guard_socks5([socks5] {
		caf::anon_send_exit(socks5, caf::exit_reason::kill);
	});

	uint16_t port = 0;
	{
		caf::scoped_actor self;
		self->sync_send(socks5, caf::publish_atom::value, port).await(
			[&port] (caf::ok_atom, uint16_t socks5_port) {
				port = socks5_port;
			},
			[] (caf::error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
			}
		);
	}
	ASSERT_NE(0, port);

	for (auto i = 0; i < 10; ++i) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_NE(-1, fd);
		scope_guard guard_fd([fd] { close(fd); });

		sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");
		sin.sin_port = htons(port);
		ASSERT_EQ(0, connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)));

		{
			// version identifier/method selection message
			uint8_t buf[] = {0x05, 0x01, 0x00};
			send(fd, buf, sizeof(buf), 0);
		}

		{
			// method selection message
			uint8_t buf[2];
			ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
			ASSERT_EQ(0x05, buf[0]);
			ASSERT_EQ(0x00, buf[1]);
		}

		{
			// request
			uint8_t buf[] = {0x05, 0x01, 0x00, 0x03};
			send(fd, buf, sizeof(buf), 0);
			char ip[] = "127.0.0.1";
			uint8_t len = sizeof(ip) - 1;
			send(fd, &len, sizeof(len), 0);
			send(fd, ip, len, 0);
			uint16_t remote_port = htons(0);
			send(fd, &remote_port, sizeof(remote_port), 0);
		}

		{
			// reply
			uint8_t buf[4];
			ASSERT_EQ(sizeof(buf), recv(fd, buf, sizeof(buf), 0));
			EXPECT_EQ(0x05, buf[0]);
			EXPECT_EQ(0x05, buf[1]);
			EXPECT_EQ(0x00, buf[2]);
			EXPECT_EQ(0x03, buf[3]);
			uint8_t len;
			ASSERT_EQ(sizeof(len), recv(fd, &len, sizeof(len), 0));
			char ip[sizeof("127.0.0.1")];
			ASSERT_EQ(len, recv(fd, ip, len, 0));
			EXPECT_STREQ("127.0.0.1", ip);
			uint16_t remote_port;
			ASSERT_EQ(sizeof(remote_port), recv(fd, &remote_port, sizeof(remote_port), 0));
			EXPECT_EQ(htons(0), remote_port);
		}
	}
}
