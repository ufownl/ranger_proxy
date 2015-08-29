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
#include "socks5_service.hpp"
#include "gate_service.hpp"

using namespace ranger;
using namespace ranger::proxy;

int bootstrap(int argc, char* argv[]) {
	std::string host;
	uint16_t port = 1080;
	std::string pwd;
	std::string remote_host;
	uint16_t remote_port = 0;

	auto res = message_builder(argv + 1, argv + argc).extract_opts({
		{"host,H", "set host", host},
		{"port,p", "set port (default: 1080)", port},
		{"password", "set password (default: empty)", pwd},
		{"gate,G", "run in gate mode"},
		{"remote_host", "set remote host (only used in gate mode)", remote_host},
		{"remote_port", "set remote port (only used in gate mode)", remote_port}
	});

	if (!res.error.empty()) {
		std::cout << res.error << std::endl;
		return 1;
	}

	if (res.opts.count("help") > 0) {
		std::cout << res.helptext << std::endl;
		return 0;
	}

	int ret = 0;

	if (res.opts.count("gate") > 0) {
		std::vector<uint8_t> key(pwd.begin(), pwd.end());
		std::vector<uint8_t> ivec;
		auto serv = spawn_io(gate_service_impl);
		scoped_actor self;
		self->send(serv, add_atom::value, remote_host, remote_port, key, ivec);
		if (host.empty()) {
			scoped_actor self;
			self->sync_send(serv, publish_atom::value, port).await(
				[] (ok_atom, uint16_t) {
					std::cout << "INFO: ranger_proxy(gate mode) start-up successfully" << std::endl;
				},
				[&ret] (error_atom, const std::string& what) {
					std::cout << "ERROR: " << what << std::endl;
					ret = 1;
				}
			);
		} else {
			scoped_actor self;
			self->sync_send(serv, publish_atom::value, host, port).await(
				[] (ok_atom, uint16_t) {
					std::cout << "INFO: ranger_proxy(gate mode) start-up successfully" << std::endl;
				},
				[&ret] (error_atom, const std::string& what) {
					std::cout << "ERROR: " << what << std::endl;
					ret = 1;
				}
			);
		}

		if (ret) {
			anon_send_exit(serv, exit_reason::kill);
		}
	} else {
		std::vector<uint8_t> key(pwd.begin(), pwd.end());
		std::vector<uint8_t> ivec;
		auto serv = spawn_io(socks5_service_impl);
		if (host.empty()) {
			scoped_actor self;
			self->send(serv, encrypt_atom::value, key, ivec);
			self->sync_send(serv, publish_atom::value, port).await(
				[] (ok_atom, uint16_t) {
					std::cout << "INFO: ranger_proxy start-up successfully" << std::endl;
				},
				[&ret] (error_atom, const std::string& what) {
					std::cout << "ERROR: " << what << std::endl;
					ret = 1;
				}
			);
		} else {
			scoped_actor self;
			self->send(serv, encrypt_atom::value, key, ivec);
			self->sync_send(serv, publish_atom::value, host, port).await(
				[] (ok_atom, uint16_t) {
					std::cout << "INFO: ranger_proxy start-up successfully" << std::endl;
				},
				[&ret] (error_atom, const std::string& what) {
					std::cout << "ERROR: " << what << std::endl;
					ret = 1;
				}
			);
		}

		if (ret) {
			anon_send_exit(serv, exit_reason::kill);
		}
	}

	return ret;
}

int main(int argc, char* argv[]) {
	int ret = bootstrap(argc, argv);
	await_all_actors_done();
	shutdown();
	return ret;
}
