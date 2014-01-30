/*
 * This file is part of fernmelder
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

#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <stdint.h>
#include <cstdlib>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <resolv.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "dns.h"


using namespace std;
using namespace net_headers;


const uint8_t dns_max_label = 63;


/*  "\003foo\003bar\000" -> foo.bar
 */
int qname2host(const string &msg, string &result)
{
	string::size_type i = 0;
	uint8_t len = 0;

	result = "";
	string s = "";
	try {
		s.reserve(msg.length());
	} catch (...) {
		return -1;
	}

	while ((len = msg[i]) != 0) {
		if (len > dns_max_label) {
			result = s;
			return 0;
		}
		if (len + i + 1 > msg.size())
			return -1;

		s += msg.substr(i + 1, len);
		s += ".";
		i += len + 1;
	}
	result = s;
	return i + 1;
}


/* "\003foo\003bar\02ab\02de\0", "\02ab\02de\0"-> foobar.ab.de
 * (to unsplit the automatically splitted large labels from host2qname())
 * Un-splitting of domains stops if encoded_domain is seen
 */
int qname2host(const string &msg, string &result, const string &encoded_domain)
{
	string::size_type i = 0;
	uint8_t len = 0;
	bool add_dot = 0;

	result = "";
	string s = "";

	try {
		s.reserve(msg.length());
	} catch (...) {
		return -1;
	}

	while ((len = msg[i]) != 0) {
		if (len > dns_max_label) {
			result = s;
			return 0;
		}
		if (len + i + 1 > msg.size())
			return -1;

		if (add_dot)
			s += ".";
		s += msg.substr(i + 1, len);
		i += len + 1;
		if (encoded_domain == msg.substr(i, encoded_domain.size()))
			add_dot = 1;
	}
	result = s;
	return i + 1;
}


/* "foo.bar" -> "\003foo\003bar\000"
 * automatically splits labels larger than 63 byte into
 * sub-domains
 */
int host2qname(const string &host, string &result)
{
	string split_host = "";
	string::size_type pos1 = 0, pos2 = 0;

	for (;pos1 < host.size();) {
		pos2 = host.find(".", pos1);
		if (pos2 == string::npos) {
			split_host += host.substr(pos1);
			break;
		}

		if (pos2 - pos1 > dns_max_label) {
			split_host += host.substr(pos1, dns_max_label);
			pos1 += dns_max_label;
		} else {
			split_host += host.substr(pos1, pos2 - pos1);
			pos1 = pos2 + 1;
		}

		split_host += ".";
	}

	try {
		result.clear();
		result.reserve(split_host.length() + 2);
		result.resize(split_host.length() + 2);
	} catch (...) {
		return -1;
	}

	int i = 0, j = 0, k = 0, l = 0;
	uint8_t how_much = 0;

	while (i < (int)split_host.length()) {
		l = i;
		how_much = 0;
		while (split_host[i] != '.' && i != (int)split_host.length()) {
			++how_much;
			++i;
		}
		result[j] = how_much;
		++j;
		i = l;
		for (k = 0; k < how_much; j++, i++, k++)
			result[j] = split_host[i];
		++i;
	}
	result[j] = '\0';
	return j + 1;
}


int DNS::query(const string &host, string &result, uint16_t qtype)
{
	static uint16_t seq = 0;
	err = "";
	result = "";
	string qname = "";

	dnshdr dnsh;
	memset(&dnsh, 0, sizeof(dnsh));
	dnsh.id = ++seq;
	dnsh.rd = 1;
	dnsh.q_count = htons(1);

	size_t buflen = sizeof(dnsh) + 2*sizeof(uint16_t);
	if (host2qname(host, qname) < 0)
		return build_error("query: cannot encode hostname");
	buflen += qname.length();

	char *buf = new (nothrow) char[buflen];
	if (!buf)
		return build_error("query: OOM");

	memcpy(buf, &dnsh, sizeof(dnsh));
	size_t idx = sizeof(dnsh);

	memcpy(buf + idx, qname.c_str(), qname.size());
	idx += qname.size();
	*(uint16_t *)&buf[idx] = htons(qtype);
	idx += sizeof(uint16_t);
	*(uint16_t *)&buf[idx] =  htons(1); // INET
	idx += sizeof(uint16_t);

	result.assign(buf, buflen);

	xid2name[seq] = host;

	delete [] buf;
	return 0;
}


DNS::DNS(int af, int t)
{
	family = af;
	type = t;
	sock = -1;
	err = "";
	secs = 1000;
}


DNS::~DNS()
{
	if (sock >= 0)
		close(sock);

	for (auto i : ns_map) {
		freeaddrinfo(i.first);
	}
}


int DNS::add_ns(const string &host, const string &port)
{
	err = "";

	// just one DNS server for TCP DNS
	if (type == SOCK_STREAM && ns_map.size() > 0)
		return 0;

	struct addrinfo *ai = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = type;

 	int e;
	if ((e = getaddrinfo(host.c_str(), port.c_str(), &hints, &ai)) != 0) {
		err = "DNS::add_ns:getaddrinfo:";
		err += gai_strerror(e);
		return -1;
	}

	ns_map[ai] = ai->ai_addrlen;

	// do not free, as we keep a pointer in the ns_map
	//freeaddrinfo(ai);
	return 0;
}


int DNS::parse_response(const string &msg, string &name, multimap<string, string> &result)
{
	name = "";
	result.clear();

	if (msg.size() < sizeof(dnshdr) + 4 + 16)
		return build_error("parse_response: response too short");

	const dnshdr *hdr = (const dnshdr *)msg.c_str();
	const char *qname = msg.c_str() + sizeof(dnshdr);

	if (ntohs(hdr->q_count) != 1)
		return build_error("parse_response: invalid packet (1)");

	string fqdn = "";
	int nl = 0;	// length of DNS encoded name
	if ((nl = qname2host(string(qname, msg.size() - sizeof(dnshdr)), fqdn)) <= 0)
		return build_error("parse_response: invalid packet (2)");

	name = fqdn;

	auto it = xid2name.find(hdr->id);
	if (it != xid2name.end()) {
		if (name.find(it->second) == string::npos) {
			return 0;
		}
		xid2name.erase(it);
	} else {
		return 0;
	}

	if (hdr->rcode != 0) {
		result.insert(pair<string, string>("0\tIN", "NXDOMAIN"));
		return 1;
	}

	if (msg.size() < sizeof(dnshdr) + nl + 4 + sizeof(dns_rr))
		return build_error("parse_response: invalid packet (3)");

	const char *idx = reinterpret_cast<const char *>(msg.c_str() + sizeof(dnshdr) + nl + 2*sizeof(uint16_t));

	const dns_rr *rr = NULL;
	char ip_buf[128], ttl[32], exp_dn[MAXDNAME];
	string s = "";
	in_addr in;
	in6_addr in6;

	for (int i = 0; i < ntohs(hdr->a_count); ++i) {
		// compressed label?
		if ((uint8_t)idx[0] > dns_max_label)
			idx += 2;
		else
			idx += nl;

		if (idx + sizeof(dns_rr) > msg.c_str() + msg.size())
			return build_error("parse_response: invalid packet (4)");

		rr = reinterpret_cast<const dns_rr *>(idx);
		idx += sizeof(dns_rr);

		if (idx + ntohs(rr->len) > msg.c_str() + msg.size())
			return build_error("parse_response: invalid packet (5)");

		memset(ttl, 0, sizeof(ttl));
		snprintf(ttl, sizeof(ttl), "%d", ntohl(rr->ttl));
		s = ttl;
		s += "\tIN\t";

		if (rr->type == htons(dns_type::A)) {
			memset(ip_buf, 0, sizeof(ip_buf));
			memcpy(&in.s_addr, idx, sizeof(in.s_addr));
			inet_ntop(AF_INET, &in, ip_buf, sizeof(ip_buf));
			s += "A\t";
			result.insert(pair<string, string>(s,  ip_buf));
		} else if (rr->type == htons(dns_type::CNAME)) {
			fqdn = "";
			if ((nl = qname2host(string(idx, ntohs(rr->len)), fqdn)) < 0)
				return build_error("parse_response: invalid packet (6)");
			// compressed
			else if (nl == 0) {
				memset(exp_dn, 0, sizeof(exp_dn));
				ns_name_uncompress(reinterpret_cast<const unsigned char*>(msg.c_str()),
				                   reinterpret_cast<const unsigned char*>(msg.c_str() + msg.size() + 1),
				                   reinterpret_cast<const unsigned char*>(idx), exp_dn, sizeof(exp_dn));
				fqdn = string(exp_dn);
				fqdn += ".";
			}
			s += "CNAME\t";
			result.insert(pair<string, string>(s, fqdn));
		} else if (rr->type == htons(dns_type::AAAA)) {
			memset(ip_buf, 0, sizeof(ip_buf));
			memcpy(&in6, idx, sizeof(in6));
			inet_ntop(AF_INET6, &in6, ip_buf, sizeof(ip_buf));
			s += "AAAA\t";
			result.insert(pair<string, string>(s,  ip_buf));
		}

		idx += ntohs(rr->len);
	}

	if (result.size() == 0)
		return -1;

	return 1;
}


int DNS::rebind()
{
	// no rebinds necessary for TCP DNS
	if (type == SOCK_STREAM)
		return 0;

	if (sock >= 0)
		close(sock);

	if ((sock = socket(family, type, 0)) < 0)
		return build_error("rebind::socket");
	int fl = fcntl(sock, F_GETFL);
	if (fl >= 0)
		fcntl(sock, F_SETFL, fl|O_NONBLOCK);

	timeval tv;
	memset(&tv, 0, sizeof(tv));
	gettimeofday(&tv, NULL);

	if (family == AF_INET) {
		sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		for (int i = 0;; ++i) {
			sin.sin_port = htons(tv.tv_usec + i % 0xffff);
			if (bind(sock, (sockaddr *)&sin, sizeof(sin)) == 0)
				break;
		}
	} else {
		sockaddr_in6 sin6;
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		for (int i = 0;; ++i) {
			sin6.sin6_port = htons(tv.tv_usec + i % 0xffff);
			if (bind(sock, (sockaddr *)&sin6, sizeof(sin6)) == 0)
				break;
		}

	}
	return 0;
}


// poll implemented by means of select :-)
int DNS::poll(int sec)
{
	timeval tv;

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = sec;
	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(sock, &rset);

	if (select(sock + 1, &rset, NULL, NULL, &tv) == 1)
		return 1;

	return 0;
}


int DNS::send(vector<string> &msgs)
{
	if (sock < 0) {
		if ((sock = socket(family, type, 0)) < 0)
			return build_error("send::socket");
		int fl = fcntl(sock, F_GETFL);
		if (fl >= 0)
			fcntl(sock, F_SETFL, fl|O_NONBLOCK);
	}

	if (msgs.size() == 0)
		return 0;

	int r = 0;
	string msg = "";
	for (auto it = ns_map.begin(); msgs.size() > 0;) {
		msg = msgs.back();

		r = ::sendto(sock, msg.c_str(), msg.length(), 0, it->first->ai_addr,
		             it->second);
		usleep(secs);

		if (r < 0 && errno == EAGAIN)
			continue;
		else if (r < 0)
			return build_error("send::send");

		msgs.pop_back();
		++it;
		if (it == ns_map.end())
			it = ns_map.begin();
	}
	return 0;
}



int DNS::recv(string &msg)
{
	msg = "";

	if (sock < 0)
		return build_error("recv: No open socket");

	char buf[1024];
	memset(buf, 0, sizeof(buf));
	ssize_t r = ::recv(sock, buf, sizeof(buf), 0);
	if (r < 0 && errno == EAGAIN)
		return 0;
	else if (r < 0)
		return build_error("recv::recv");

	msg = string(buf, r);
	return 1;
}

