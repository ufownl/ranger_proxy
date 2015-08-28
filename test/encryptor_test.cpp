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
#include "aes_cfb128_encryptor.cpp"

TEST_F(ranger_proxy_test, aes_cfb128_encryptor_128) {
	std::string str = "ABCDEFGHIJKLMNOP";
	ASSERT_EQ(128 / 8, str.size());

	std::vector<uint8_t> key(str.begin(), str.end());
	std::vector<uint8_t> ivec;
	auto enc = caf::spawn(ranger::proxy::aes_cfb128_encryptor_impl, key, ivec);
	scope_guard guard_end([enc] {
		caf::anon_send_exit(enc, caf::exit_reason::kill);
	});

	std::vector<uint8_t> plain = {'H', 'e', 'l', 'l', 'o'};
	std::vector<uint8_t> cipher;
	{
		caf::scoped_actor self;
		self->sync_send(enc, ranger::proxy::encrypt_atom::value, plain).await(
			[&plain, &cipher] (const std::vector<uint8_t>& out) {
				cipher = out;
			}
		);
	}
	EXPECT_NE(plain, cipher);

	std::vector<uint8_t> decrypt;
	{
		caf::scoped_actor self;
		self->sync_send(enc, ranger::proxy::decrypt_atom::value, cipher).await(
			[&cipher, &decrypt] (const std::vector<uint8_t>& out) {
				decrypt = out;
			}
		);
	}
	EXPECT_NE(cipher, decrypt);
	EXPECT_EQ(plain, decrypt);
}

TEST_F(ranger_proxy_test, aes_cfb128_encryptor_192) {
	std::string str = "ABCDEFGHIJKLMNOPQRSTUVWX";
	ASSERT_EQ(192 / 8, str.size());

	std::vector<uint8_t> key(str.begin(), str.end());
	std::vector<uint8_t> ivec;
	auto enc = caf::spawn(ranger::proxy::aes_cfb128_encryptor_impl, key, ivec);
	scope_guard guard_end([enc] {
		caf::anon_send_exit(enc, caf::exit_reason::kill);
	});

	std::vector<uint8_t> plain = {'W', 'o', 'r', 'l', 'd'};
	std::vector<uint8_t> cipher;
	{
		caf::scoped_actor self;
		self->sync_send(enc, ranger::proxy::encrypt_atom::value, plain).await(
			[&plain, &cipher] (const std::vector<uint8_t>& out) {
				cipher = out;
			}
		);
	}
	EXPECT_NE(plain, cipher);

	std::vector<uint8_t> decrypt;
	{
		caf::scoped_actor self;
		self->sync_send(enc, ranger::proxy::decrypt_atom::value, cipher).await(
			[&cipher, &decrypt] (const std::vector<uint8_t>& out) {
				decrypt = out;
			}
		);
	}
	EXPECT_NE(cipher, decrypt);
	EXPECT_EQ(plain, decrypt);
}

TEST_F(ranger_proxy_test, aes_cfb128_encryptor_256) {
	std::string str = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";
	ASSERT_EQ(256 / 8, str.size());

	std::vector<uint8_t> key(str.begin(), str.end());
	std::vector<uint8_t> ivec;
	auto enc = caf::spawn(ranger::proxy::aes_cfb128_encryptor_impl, key, ivec);
	scope_guard guard_end([enc] {
		caf::anon_send_exit(enc, caf::exit_reason::kill);
	});

	std::vector<uint8_t> plain = {'R', 'a', 'n', 'g', 'e', 'r'};
	std::vector<uint8_t> cipher;
	{
		caf::scoped_actor self;
		self->sync_send(enc, ranger::proxy::encrypt_atom::value, plain).await(
			[&plain, &cipher] (const std::vector<uint8_t>& out) {
				cipher = out;
			}
		);
	}
	EXPECT_NE(plain, cipher);

	std::vector<uint8_t> decrypt;
	{
		caf::scoped_actor self;
		self->sync_send(enc, ranger::proxy::decrypt_atom::value, cipher).await(
			[&cipher, &decrypt] (const std::vector<uint8_t>& out) {
				decrypt = out;
			}
		);
	}
	EXPECT_NE(cipher, decrypt);
	EXPECT_EQ(plain, decrypt);
}
