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
#include <rapidxml.hpp>
#include <rapidxml_utils.hpp>
#include <unistd.h>
#include <string.h>

using namespace ranger;
using namespace ranger::proxy;
using namespace ranger::proxy::experimental;

int bootstrap_with_config_impl(rapidxml::xml_node<>* root, bool verbose) {
	auto next = root->next_sibling("ranger_proxy");
	if (next) {
		auto pid = fork();
		if (pid == 0) {
			return bootstrap_with_config_impl(next, verbose);
		} else if (pid < 0) {
			std::cout << "ERROR: Failed in calling fork()" << std::endl;
			return 1;
		}
	}

	int ret = 0;
	std::string host;
	auto node = root->first_node("host");
	if (node) {
		host = node->value();
	}

	uint16_t port = 1080;
	node = root->first_node("port");
	if (node) {
		port = atoi(node->value());
	}

	node = root->first_node("gate");
	if (node && atoi(node->value())) {
		auto serv = spawn_io(gate_service_impl);
		scoped_actor self;
		for (auto j = root->first_node("remote_host"); j; j = j->next_sibling("remote_host")) {
			std::string remote_addr;
			node = j->first_node("address");
			if (node) {
				remote_addr = node->value();
			}

			uint16_t remote_port = 0;
			node = j->first_node("port");
			if (node) {
				remote_port = atoi(node->value());
			}

			std::vector<uint8_t> key;
			node = j->first_node("key");
			if (node) {
				key.insert(	key.end(),
							node->value(),
							node->value() + strlen(node->value()));
			}

			int period = 0;
			node = j->first_node("period");
			if (node) {
				char* end;
				period = strtoul(node->value(), &end, 10);
			}

			bool zlib = false;
			node = j->first_node("zlib");
			if (node && atoi(node->value())) {
				zlib = true;
			}

			self->send(serv, add_atom::value, remote_addr, remote_port, key, period, zlib);
		}

		auto ok_hdl = [] (ok_atom, uint16_t) {
			std::cout << "INFO: ranger_proxy(gate mode) start-up successfully" << std::endl;
		};
		auto err_hdl = [&ret] (error_atom, const std::string& what) {
			std::cout << "ERROR: " << what << std::endl;
			ret = 1;
		};
		if (host.empty()) {
			self->sync_send(serv, publish_atom::value, port).await(ok_hdl, err_hdl);
		} else {
			self->sync_send(serv, publish_atom::value, host, port).await(ok_hdl, err_hdl);
		}

		if (ret) {
			anon_send_exit(serv, exit_reason::kill);
		}
	} else {
		auto serv = spawn_io(socks5_service_impl, verbose);
		scoped_actor self;
		for (auto j = root->first_node("user"); j; j = j->next_sibling("user")) {
			node = j->first_node("username");
			if (node) {
				std::string username = node->value();
				std::string password;
				node = j->first_node("password");
				if (node) {
					password = node->value();
				}

				self->sync_send(serv, add_atom::value, username, password).await(
					[] (bool result, const std::string& username) {
						if (result) {
							std::cout << "INFO: Add user[" << username << "] successfully" << std::endl;
						} else {
							std::cout << "ERROR: Fail in adding user[" << username << "]" << std::endl;
						}
					}
				);
			}
		}

		std::vector<uint8_t> key;
		node = root->first_node("key");
		if (node) {
			key.insert(	key.end(),
						node->value(),
						node->value() + strlen(node->value()));
		}

		int period = 0;
		node = root->first_node("period");
		if (node) {
			char* end;
			period = strtoul(node->value(), &end, 10);
		}

		self->send(serv, encrypt_atom::value, key, period);

		node = root->first_node("zlib");
		if (node && atoi(node->value())) {
			self->send(serv, zlib_atom::value, true);
		}

		auto ok_hdl = [] (ok_atom, uint16_t) {
			std::cout << "INFO: ranger_proxy start-up successfully" << std::endl;
		};
		auto err_hdl = [&ret] (error_atom, const std::string& what) {
			std::cout << "ERROR: " << what << std::endl;
			ret = 1;
		};
		if (host.empty()) {
			self->sync_send(serv, publish_atom::value, port).await(ok_hdl, err_hdl);
		} else {
			self->sync_send(serv, publish_atom::value, host, port).await(ok_hdl, err_hdl);
		}

		if (ret) {
			anon_send_exit(serv, exit_reason::kill);
		}
	}
	return ret;
}

int bootstrap_with_config(const std::string& config, bool verbose) {
	try {
		rapidxml::file<> fin(config.c_str());
		rapidxml::xml_document<> doc;
		doc.parse<0>(fin.data());
		auto root = doc.first_node("ranger_proxy");
		if (root) {
			return bootstrap_with_config_impl(root, verbose);
		}
		return 0;
	} catch (const rapidxml::parse_error& e) {
		std::cout << "ERROR: " << e.what() << " [" << e.where<const char>() << "]" << std::endl;
		return 1;
	} catch (const std::runtime_error& e) {
		std::cout << "ERROR: " << e.what() << std::endl;
		return 1;
	}
}

int bootstrap(int argc, char* argv[]) {
	std::string host;
	uint16_t port = 1080;
	std::string username;
	std::string password;
	std::string key_src;
	int period = 0;
	std::string remote_host;
	uint16_t remote_port = 0;
	std::string config;

	auto res = message_builder(argv + 1, argv + argc).extract_opts({
		{"host,H", "set host", host},
		{"port,p", "set port (default: 1080)", port},
		{"username", "set username (it will enable username auth method)", username},
		{"password", "set password", password},
		{"key,k", "set key (default: empty)", key_src},
		{"period", "set initial vector update period (default: 0)", period},
		{"zlib,z", "enable zlib compression (default: disable)"},
		{"gate,G", "run in gate mode"},
		{"remote_host", "set remote host (only used in gate mode)", remote_host},
		{"remote_port", "set remote port (only used in gate mode)", remote_port},
		{"config", "load a config file (it will disable all options above)", config},
		{"verbose,v", "enable verbose output (default: disable)"},
		{"daemon,d", "run as daemon"}
	});

	if (!res.error.empty()) {
		std::cout << res.error << std::endl;
		return 1;
	}

	if (res.opts.count("help") > 0) {
		std::cout << res.helptext << std::endl;
		return 0;
	}

	if (res.opts.count("daemon") > 0) {
		auto pid = fork();
		if (pid > 0) {
			return 0;
		} else if (pid < 0) {
			std::cout << "ERROR: Failed in calling fork()" << std::endl;
			return 1;
		}
	}

	int ret = 0;

	if (res.opts.count("config") > 0) {
		ret = bootstrap_with_config(config, res.opts.count("verbose") > 0);
	} else if (res.opts.count("gate") > 0) {
		scoped_actor self;
		auto serv = spawn_io(gate_service_impl);
		std::vector<uint8_t> key(key_src.begin(), key_src.end());
		self->send(	serv, add_atom::value, remote_host, remote_port,
					key, period, res.opts.count("zlib") > 0);
		auto ok_hdl = [] (ok_atom, uint16_t) {
			std::cout << "INFO: ranger_proxy(gate mode) start-up successfully" << std::endl;
		};
		auto err_hdl = [&ret] (error_atom, const std::string& what) {
			std::cout << "ERROR: " << what << std::endl;
			ret = 1;
		};
		if (host.empty()) {
			self->sync_send(serv, publish_atom::value, port).await(ok_hdl, err_hdl);
		} else {
			self->sync_send(serv, publish_atom::value, host, port).await(ok_hdl, err_hdl);
		}

		if (ret) {
			anon_send_exit(serv, exit_reason::kill);
		}
	} else {
		auto serv = spawn_io(socks5_service_impl, res.opts.count("verbose") > 0);
		scoped_actor self;
		if (!username.empty()) {
			self->sync_send(serv, add_atom::value, username, password).await(
				[] (bool result, const std::string& username) {
					if (result) {
						std::cout << "INFO: Add user[" << username << "] successfully" << std::endl;
					} else {
						std::cout << "ERROR: Fail in adding user[" << username << "]" << std::endl;
					}
				}
			);
		}
		std::vector<uint8_t> key(key_src.begin(), key_src.end());
		self->send(serv, encrypt_atom::value, key, period);
		self->send(serv, zlib_atom::value, res.opts.count("zlib") > 0);
		auto ok_hdl = [] (ok_atom, uint16_t) {
			std::cout << "INFO: ranger_proxy start-up successfully" << std::endl;
		};
		auto err_hdl = [&ret] (error_atom, const std::string& what) {
			std::cout << "ERROR: " << what << std::endl;
			ret = 1;
		};
		if (host.empty()) {
			self->sync_send(serv, publish_atom::value, port).await(ok_hdl, err_hdl);
		} else {
			self->sync_send(serv, publish_atom::value, host, port).await(ok_hdl, err_hdl);
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
