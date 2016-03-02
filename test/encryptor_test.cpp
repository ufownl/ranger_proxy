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
#include "zlib_encryptor.cpp"
#include "logger_ostream.cpp"

TEST_F(ranger_proxy_test, aes_cfb128_encryptor_128) {
  std::string str = "ABCDEFGHIJKLMNOP";
  ASSERT_EQ(128 / 8, str.size());

  std::vector<uint8_t> key(str.begin(), str.end());
  std::vector<uint8_t> ivec;
  auto enc =
    m_sys->spawn(ranger::proxy::aes_cfb128_encryptor_impl, key, ivec);
  auto enc_guard = make_scope_guard([enc] {
    caf::anon_send_exit(enc, caf::exit_reason::kill);
  });
  auto enc_fv = caf::make_function_view(enc);

  std::vector<char> plain = {'H', 'e', 'l', 'l', 'o'};
  auto cipher = enc_fv(ranger::proxy::encrypt_atom::value, plain);
  EXPECT_NE(plain, std::get<1>(cipher));

  auto decrypt =
    enc_fv(ranger::proxy::decrypt_atom::value, std::get<1>(cipher));
  EXPECT_NE(std::get<1>(cipher), std::get<1>(decrypt));
  EXPECT_EQ(plain, std::get<1>(decrypt));
}

TEST_F(ranger_proxy_test, aes_cfb128_encryptor_192) {
  std::string str = "ABCDEFGHIJKLMNOPQRSTUVWX";
  ASSERT_EQ(192 / 8, str.size());

  std::vector<uint8_t> key(str.begin(), str.end());
  std::vector<uint8_t> ivec;
  auto enc =
    m_sys->spawn(ranger::proxy::aes_cfb128_encryptor_impl, key, ivec);
  auto enc_guard = make_scope_guard([enc] {
    caf::anon_send_exit(enc, caf::exit_reason::kill);
  });
  auto enc_fv = caf::make_function_view(enc);

  std::vector<char> plain = {'W', 'o', 'r', 'l', 'd'};
  auto cipher = enc_fv(ranger::proxy::encrypt_atom::value, plain);
  EXPECT_NE(plain, std::get<1>(cipher));

  auto decrypt =
    enc_fv(ranger::proxy::decrypt_atom::value, std::get<1>(cipher));
  EXPECT_NE(std::get<1>(cipher), std::get<1>(decrypt));
  EXPECT_EQ(plain, std::get<1>(decrypt));
}

TEST_F(ranger_proxy_test, aes_cfb128_encryptor_256) {
  std::string str = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";
  ASSERT_EQ(256 / 8, str.size());

  std::vector<uint8_t> key(str.begin(), str.end());
  std::vector<uint8_t> ivec;
  auto enc =
    m_sys->spawn(ranger::proxy::aes_cfb128_encryptor_impl, key, ivec);
  auto enc_guard = make_scope_guard([enc] {
    caf::anon_send_exit(enc, caf::exit_reason::kill);
  });
  auto enc_fv = caf::make_function_view(enc);

  std::vector<char> plain = {'R', 'a', 'n', 'g', 'e', 'r'};
  auto cipher = enc_fv(ranger::proxy::encrypt_atom::value, plain);
  EXPECT_NE(plain, std::get<1>(cipher));

  auto decrypt =
    enc_fv(ranger::proxy::decrypt_atom::value, std::get<1>(cipher));
  EXPECT_NE(std::get<1>(cipher), std::get<1>(decrypt));
  EXPECT_EQ(plain, std::get<1>(decrypt));
}

TEST_F(ranger_proxy_test, zlib_encryptor) {
  auto enc = m_sys->spawn(ranger::proxy::zlib_encryptor_impl, ranger::proxy::encryptor());
  auto enc_guard = make_scope_guard([enc] {
    caf::anon_send_exit(enc, caf::exit_reason::kill);
  });
  auto enc_fv = caf::make_function_view(enc);

  std::vector<char> plain(8192, 'a');
  auto cipher = enc_fv(ranger::proxy::encrypt_atom::value, plain);
  EXPECT_NE(plain, std::get<1>(cipher));

  auto decrypt =
    enc_fv(ranger::proxy::decrypt_atom::value, std::get<1>(cipher));
  EXPECT_NE(std::get<1>(cipher), std::get<1>(decrypt));
  EXPECT_EQ(plain, std::get<1>(decrypt));
}

TEST_F(ranger_proxy_test, zlib_aes_cfb128_encryptor_256) {
  std::string str = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";
  ASSERT_EQ(256 / 8, str.size());

  std::vector<uint8_t> key(str.begin(), str.end());
  std::vector<uint8_t> ivec;
  
  auto zlib_enc = m_sys->spawn(ranger::proxy::aes_cfb128_encryptor_impl, key, ivec);
  auto zlib_enc_guard = make_scope_guard([zlib_enc] {
    caf::anon_send_exit(zlib_enc, caf::exit_reason::kill);
  });

  auto enc = m_sys->spawn(ranger::proxy::zlib_encryptor_impl, zlib_enc);
  auto enc_guard = make_scope_guard([enc] {
    caf::anon_send_exit(enc, caf::exit_reason::kill);
  });
  auto enc_fv = caf::make_function_view(enc);

  std::vector<char> plain(8192, 'b');
  auto cipher = enc_fv(ranger::proxy::encrypt_atom::value, plain);
  EXPECT_NE(plain, std::get<1>(cipher));

  auto decrypt =
    enc_fv(ranger::proxy::decrypt_atom::value, std::get<1>(cipher));
  EXPECT_NE(std::get<1>(cipher), std::get<1>(decrypt));
  EXPECT_EQ(plain, std::get<1>(decrypt));
}
