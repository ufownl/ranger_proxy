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
#include "zlib_encryptor.hpp"
#include "logger_ostream.hpp"
#include <stdexcept>
#include <new>

namespace ranger { namespace proxy {

zlib_state::zlib_state(encryptor::pointer self)
  : m_self(self) {
  // nop
}

zlib_state::~zlib_state() {
  deflateEnd(&m_deflate_strm);
  inflateEnd(&m_inflate_strm);
}

void zlib_state::init(const encryptor& enc) {
  m_encryptor = enc;
  
  auto err_code = deflateInit(&m_deflate_strm, Z_BEST_COMPRESSION);
  if (err_code == Z_MEM_ERROR) {
    throw std::bad_alloc();
  } else if (err_code != Z_OK) {
    log(m_self) << "ERROR: " << m_deflate_strm.msg << std::endl;
    throw std::runtime_error(m_deflate_strm.msg);
  }

  err_code = inflateInit(&m_inflate_strm);
  if (err_code == Z_MEM_ERROR) {
    throw std::bad_alloc();
  } else if (err_code != Z_OK) {
    log(m_self) << "ERROR: " << m_inflate_strm.msg << std::endl;
    throw std::runtime_error(m_inflate_strm.msg);
  }
}

zlib_state::encrypt_promise_type zlib_state::encrypt(const std::vector<char>& in) {
  auto promise = m_self->make_response_promise<encrypt_promise_type>();
  if (m_encryptor.unsafe()) {
    promise.deliver(encrypt_atom::value, compress(in));
  } else {
    m_self->request(m_encryptor, infinite,
                    encrypt_atom::value, compress(in)).then(
      [promise] (encrypt_atom, const std::vector<char>& buf) mutable {
        promise.deliver(encrypt_atom::value, buf);
      }
    );
  }

  return promise;
}

zlib_state::decrypt_promise_type zlib_state::decrypt(const std::vector<char>& in) {
  auto promise = m_self->make_response_promise<decrypt_promise_type>();
  if (m_encryptor.unsafe()) {
    promise.deliver(decrypt_atom::value, uncompress(in));
  } else {
    m_self->request(m_encryptor, infinite,
                    decrypt_atom::value, in).then(
      [this, promise] (decrypt_atom, const std::vector<char>& buf) mutable {
        promise.deliver(decrypt_atom::value, uncompress(buf));
      }
    );
  }

  return promise;
}

std::vector<char> zlib_state::compress(const std::vector<char>& in) {
  std::vector<char> out;
  std::vector<Bytef> in_buf(in.begin(), in.end());
  m_deflate_strm.next_in = in_buf.data();
  m_deflate_strm.avail_in = in_buf.size();
  do {
    Bytef buf[BUFFER_SIZE];
    m_deflate_strm.next_out = buf;
    m_deflate_strm.avail_out = sizeof(buf);
    deflate(&m_deflate_strm, Z_SYNC_FLUSH);
    size_t len = sizeof(buf) - m_deflate_strm.avail_out;
    if (len > 0) {
      out.insert(out.end(), buf, buf + len);
    }
  } while (m_deflate_strm.avail_out == 0);

  return out;
}

std::vector<char> zlib_state::uncompress(const std::vector<char>& in) {
  std::vector<char> out;
  std::vector<Bytef> in_buf(in.begin(), in.end());
  m_inflate_strm.next_in = in_buf.data();
  m_inflate_strm.avail_in = in_buf.size();
  do {
    Bytef buf[BUFFER_SIZE];
    m_inflate_strm.next_out = buf;
    m_inflate_strm.avail_out = sizeof(buf);
    auto err = inflate(&m_inflate_strm, Z_SYNC_FLUSH);
    if (err == Z_MEM_ERROR) {
      throw std::bad_alloc();
    } else if (err == Z_NEED_DICT || err == Z_DATA_ERROR) {
      log(m_self) << "ERROR: " << m_inflate_strm.msg << std::endl;
      throw std::runtime_error(m_inflate_strm.msg);
    }

    size_t len = sizeof(buf) - m_inflate_strm.avail_out;
    if (len > 0) {
      out.insert(out.end(), buf, buf + len);
    }
  } while (m_inflate_strm.avail_out == 0);

  return out;
}

encryptor::behavior_type
zlib_encryptor_impl(encryptor::stateful_pointer<zlib_state> self, encryptor enc) {
  self->state.init(enc);
  return {
    [self] (encrypt_atom, const std::vector<char>& data) {
      return self->state.encrypt(data);
    },
    [self] (decrypt_atom, const std::vector<char>& data) {
      return self->state.decrypt(data);
    }
  };
}

} }
