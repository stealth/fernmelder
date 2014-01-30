/*
 * This file is part of fernmelder.
 *
 * (C) 2014 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
 *
 * fernmelder is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * fernmelder is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with fernmelder.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __dns_h__
#define __dns_h__

#include <stdint.h>
#include <time.h>
#include <string>
#include <cstring>
#include <vector>
#include <list>
#include <map>
#include <errno.h>
#include <bits/endian.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "net-headers.h"



int host2qname(const std::string&, std::string&);


struct dns_command {
	char op[8];
	uint32_t nonce;
} __attribute__((packed));

extern dns_command dns_timer_cmd;


class DNS {

	int sock, family, type, secs;

	std::string err;
	std::map<addrinfo *, socklen_t> ns_map;
	std::map<uint16_t, std::string> xid2name;

public:
	DNS(int, int t = SOCK_DGRAM);

	~DNS();

	const char *why() { return err.c_str(); };

	int build_error(const std::string &s)
	{
		err = "DNS::";
		err += s;
		if (errno) {
			err += ": ";
			err += strerror(errno);
		}
		return -1;
	}

	int query(const std::string&, std::string&, uint16_t qtype = net_headers::dns_type::A);

	int parse_response(const std::string &, std::string &, std::multimap<std::string, std::string> &);

	int add_ns(const std::string&, const std::string& port = "53");

	int send(std::vector<std::string> &);

	int recv(std::string &);

	int poll(int);

	int rebind();

	void sleep(int s)
	{
		secs = s;
	}
};

#endif

