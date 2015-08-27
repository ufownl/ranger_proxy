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

using namespace ranger;
using namespace ranger::proxy;

int bootstrap(int argc, char* argv[]) {
	std::string host;
	uint16_t port = 1080;

	auto res = message_builder(argv + 1, argv + argc).extract_opts({
		{"host,H", "set host", host},
		{"port,p", "set port (default: 1080)", port}
	});

	if (!res.error.empty()) {
		std::cout << res.error << std::endl;
		return 1;
	}

	if (res.opts.count("help") > 0) {
		std::cout << res.helptext << std::endl;
		return 0;
	}

	auto serv = spawn(socks5_service_impl);
	int ret = 0;
	if (host.empty()) {
		scoped_actor self;
		self->sync_send(serv, publish_atom::value, port).await(
			[&ret] (ok_atom, uint16_t) {
				std::cout << "INFO: ranger_proxy start-up successfully" << std::endl;
			},
			[&ret] (error_atom, const std::string& what) {
				std::cout << "ERROR: " << what << std::endl;
				ret = 1;
			}
		);
	} else {
		scoped_actor self;
		self->sync_send(serv, publish_atom::value, host, port).await(
			[&ret] (ok_atom, uint16_t) {
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

	return ret;
}

int main(int argc, char* argv[]) {
	int ret = bootstrap(argc, argv);
	await_all_actors_done();
	shutdown();
	return ret;
}
