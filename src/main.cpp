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
#include <caf/io/network/asio_multiplexer_impl.hpp>
#include <caf/policy/work_sharing.hpp>
#include <rapidxml.hpp>
#include <rapidxml_utils.hpp>
#include <thread>
#include <unistd.h>
#include <string.h>

using namespace ranger;
using namespace ranger::proxy;

int bootstrap_with_config_impl(actor_system_config& sys_cfg, rapidxml::xml_node<>* root, bool verbose) {
  auto next = root->next_sibling("ranger_proxy");
  if (next) {
    auto pid = fork();
    if (pid == 0) {
      return bootstrap_with_config_impl(sys_cfg, next, verbose);
    } else if (pid < 0) {
      std::cerr << "ERROR: Failed in calling fork()" << std::endl;
      return 1;
    }
  }

  int timeout = 300;
  auto node = root->first_node("timeout");
  if (node) {
    timeout = atoi(node->value());
  }

  std::string log;
  node = root->first_node("log");
  if (node) {
    log = node->value();
  }

  actor_system sys(sys_cfg);
  int ret = 0;
  node = root->first_node("gate");
  if (node && atoi(node->value())) {
    auto serv = sys.middleman().spawn_broker(gate_service_impl, timeout, log);
    scoped_actor self(sys);
    for (auto i = root->first_node("remote_host"); i; i = i->next_sibling("remote_host")) {
      std::string addr;
      node = i->first_node("address");
      if (node) {
        addr = node->value();
      }

      uint16_t port = 0;
      node = i->first_node("port");
      if (node) {
        port = atoi(node->value());
      }

      std::vector<uint8_t> key;
      node = i->first_node("key");
      if (node) {
        key.insert(key.end(),
                   node->value(),
                   node->value() + strlen(node->value()));
      }

      bool zlib = false;
      node = i->first_node("zlib");
      if (node && atoi(node->value())) {
        zlib = true;
      }

      self->send(serv, add_atom::value, addr, port, key, zlib);
    }

    auto ok_hdl = [] (uint16_t) {
      std::cout << "INFO: ranger_proxy(gate mode) start-up successfully" << std::endl;
    };
    auto err_hdl = [&ret] (error& e) {
      std::cerr << "ERROR: " << to_string(e.context()) << std::endl;
      ret = 1;
    };
    for (auto i = root->first_node("local_host"); i; i = i->next_sibling("local_host")) {
      std::string addr;
      node = i->first_node("address");
      if (node) {
        addr = node->value();
      }

      uint16_t port = 1080;
      node = i->first_node("port");
      if (node) {
        port = atoi(node->value());
      }

      if (addr.empty()) {
        self->request(serv, infinite, publish_atom::value,
                      port).receive(ok_hdl, err_hdl);
      } else {
        self->request(serv, infinite, publish_atom::value,
                      addr, port).receive(ok_hdl, err_hdl);
      }

      if (ret) {
        anon_send_exit(serv, exit_reason::kill);
        break;
      }
    }
  } else {
    auto serv = sys.middleman().spawn_broker(socks5_service_impl, timeout,
                                             verbose, log);
    scoped_actor self(sys);
    for (auto i = root->first_node("user"); i; i = i->next_sibling("user")) {
      node = i->first_node("username");
      if (node) {
        std::string username = node->value();
        std::string password;
        node = i->first_node("password");
        if (node) {
          password = node->value();
        }

        self->request(serv, infinite, add_atom::value,
                      username, password).receive(
          [] (bool result, const std::string& username) {
            if (result) {
              std::cout << "INFO: Add user[" << username
                        << "] successfully" << std::endl;
            } else {
              std::cerr << "ERROR: Fail in adding user["
                        << username << "]" << std::endl;
            }
          }
        );
      }
    }

    auto ok_hdl = [] (uint16_t) {
      std::cout << "INFO: ranger_proxy start-up successfully" << std::endl;
    };
    auto err_hdl = [&ret] (error& e) {
      std::cerr << "ERROR: " << to_string(e.context()) << std::endl;
      ret = 1;
    };
    for (auto i = root->first_node("local_host"); i; i = i->next_sibling("local_host")) {
      std::string addr;
      node = i->first_node("address");
      if (node) {
        addr = node->value();
      }

      uint16_t port = 1080;
      node = i->first_node("port");
      if (node) {
        port = atoi(node->value());
      }

      std::vector<uint8_t> key;
      node = i->first_node("key");
      if (node) {
        key.insert(key.end(),
                   node->value(),
                   node->value() + strlen(node->value()));
      }

      bool zlib = false;
      node = i->first_node("zlib");
      if (node && atoi(node->value())) {
        zlib = true;
      }

      if (addr.empty()) {
        self->request(serv, infinite, publish_atom::value,
                      port, key, zlib).receive(ok_hdl, err_hdl);
      } else {
        self->request(serv, infinite, publish_atom::value,
                      addr, port, key, zlib).receive(ok_hdl, err_hdl);
      }

      if (ret) {
        anon_send_exit(serv, exit_reason::kill);
        break;
      }
    }
  }
  return ret;
}

int bootstrap_with_config(actor_system_config& sys_cfg, const std::string& config, bool verbose) {
  try {
    rapidxml::file<> fin(config.c_str());
    rapidxml::xml_document<> doc;
    doc.parse<0>(fin.data());
    auto root = doc.first_node("ranger_proxy");
    if (root) {
      return bootstrap_with_config_impl(sys_cfg, root, verbose);
    }
    return 0;
  } catch (const rapidxml::parse_error& e) {
    std::cerr << "ERROR: " << e.what() << " [" << e.where<const char>() << "]" << std::endl;
    return 1;
  } catch (const std::runtime_error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}

int bootstrap(int argc, char* argv[]) {
  actor_system_config sys_cfg;
  sys_cfg.parse(argc, argv);
  sys_cfg.middleman_network_backend = atom("asio");
  sys_cfg.load<middleman>();

  std::string host;
  uint16_t port = 1080;
  std::string username;
  std::string password;
  std::string key_src;
  int timeout = 300;
  std::string log;
  std::string remote_host;
  uint16_t remote_port = 0;
  std::string config;

  auto res = sys_cfg.args_remainder.extract_opts({
    {"host,H", "set host", host},
    {"port,p", "set port (default: 1080)", port},
    {"username", "set username (it will enable username auth method)", username},
    {"password", "set password", password},
    {"key,k", "set key (default: empty)", key_src},
    {"zlib,z", "enable zlib compression (default: disable)"},
    {"timeout,t", "set timeout (default: 300)", timeout},
    {"log", "set log file path (default: empty)", log},
    {"gate,G", "run in gate mode"},
    {"remote_host", "set remote host (only used in gate mode)", remote_host},
    {"remote_port", "set remote port (only used in gate mode)", remote_port},
    {"config", "load a config file (it will disable all options above)", config},
    {"verbose,v", "enable verbose output (default: disable)"},
    {"daemon,d", "run as daemon"}
  });

  if (res.opts.count("help") > 0) {
    std::cout << res.helptext << std::endl;
    return 0;
  }

  if (res.opts.count("daemon") > 0) {
    auto pid = fork();
    if (pid > 0) {
      return 0;
    } else if (pid < 0) {
      std::cerr << "ERROR: Failed in calling fork()" << std::endl;
      return 1;
    }
  }

  if (res.opts.count("config") > 0) {
    return bootstrap_with_config(sys_cfg, config, res.opts.count("verbose") > 0);
  } else {
    actor_system sys(sys_cfg);
    if (res.opts.count("gate") > 0) {
      auto serv = sys.middleman().spawn_broker(gate_service_impl, timeout, log);
      auto serv_fv = make_function_view(serv);
      std::vector<uint8_t> key(key_src.begin(), key_src.end());
      try {
        serv_fv(add_atom::value, remote_host, remote_port, key,
                res.opts.count("zlib") > 0);
        if (host.empty()) {
          serv_fv(publish_atom::value, port);
        } else {
          serv_fv(publish_atom::value, host, port);
        }
        std::cout << "INFO: ranger_proxy(gate mode) start-up successfully" << std::endl;
      } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        anon_send_exit(serv, exit_reason::kill);
        return 1;
      }
      return 0;
    } else {
      auto serv = sys.middleman().spawn_broker(socks5_service_impl, timeout, res.opts.count("verbose") > 0, log);
      auto serv_fv = make_function_view(serv); 
      std::vector<uint8_t> key(key_src.begin(), key_src.end());
      try {
        if (!username.empty()) {
          auto res = serv_fv(add_atom::value, username, password);
          if (std::get<0>(res)) {
            std::cout << "INFO: Add user[" << std::get<1>(res) << "] successfully" << std::endl;
          } else {
            std::cerr << "ERROR: Fail in adding user[" << std::get<1>(res) << "]" << std::endl;
          }
        }
        if (host.empty()) {
          serv_fv(publish_atom::value, port, key, res.opts.count("zlib") > 0);
        } else {
          serv_fv(publish_atom::value, host, port, key, res.opts.count("zlib") > 0);
        }
        std::cout << "INFO: ranger_proxy start-up successfully" << std::endl;
      } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        anon_send_exit(serv, exit_reason::kill);
        return 1;
      }
      return 0;
    }
  }
}

int main(int argc, char* argv[]) {
  int ret = 0;
  try {
    ret = bootstrap(argc, argv);
  } catch (const std::invalid_argument& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    ret = 1;
  }
  return ret;
}
