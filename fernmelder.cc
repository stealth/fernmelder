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

#include <iostream>
#include <map>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdlib>
#include "net-headers.h"
#include "dns.h"


using namespace std;
using namespace net_headers;


void usage()
{
	cout<<"\nfernmelder <-4|-6> <-N DNS server> [-N ...] [-Q] [-s shots] [-S usec delay]\n\n"
	    <<"\t\t-4\tuse IPv4 UDP to DNS server (use before -N)\n"
	    <<"\t\t-6\tuse IPv6 UDP to DNS server (use before -N)\n"
	    <<"\t\t-Q\task for AAAA records (IPv6 mapping) rather than for A\n"
	    <<"\t\t-N\tIP or hostname of recursive DNS server to use for resolving\n"
	    <<"\t\t-A\tdo not print NXDOMAIn or CNAMEs\n"
	    <<"\t\t-s\thow many requests in a row before receiving (low values OK)\n"
	    <<"\t\t-S\tamount of usecs to sleep between send() calls to not flood server\n\n";

	exit(1);
}


int main(int argc, char **argv)
{
	DNS *dns = NULL;
	string req = "", res = "", name = "", dns_list = "";
	vector<string> v;
	multimap<string, string> result;
	int r = 0, c = 0, shots = 4, secs = 1500;
	uint16_t qtype = dns_type::A;
	bool A_only = 0;
	fd_set rset;

	while ((c = getopt(argc, argv, "N:46s:S:QA")) != -1) {
		switch (c) {
		case '4':
			dns = new (nothrow) DNS(AF_INET);
			break;
		case '6':
			dns = new (nothrow) DNS(AF_INET6);
			break;
		case 'Q':
			qtype = dns_type::AAAA;
			break;
		case 'N':
			if (dns) {
				if (dns->add_ns(optarg) < 0) {
					cerr<<dns->why()<<endl;
					exit(2);
				}
			}
			// save list for output string
			dns_list += " -N ";
			dns_list += optarg;
			break;
		case 'A':
			A_only = 1;
			break;
		case 's':
			shots = atoi(optarg);
			if (shots < 0 || shots > 0x100000)
				shots = 10;
			break;
		case 'S':
			secs = atoi(optarg);
			if (secs < 10 || secs > 0x100000)
				secs = 10;
			break;
		default:
			usage();
		}
	}

	if (!dns)
		usage();

	dns->sleep(secs);

	bool eof = 0;

	v.reserve(shots);

	cout<<"\n; <<>> fernmelder 0.3 <<>> -s "<<shots<<" -S "<<secs
	    <<dns_list;

	if (qtype == dns_type::AAAA)
		cout<<" -Q";

	if (A_only)
		cout<<" -A";

	cout<<"\n;\n";

	for (;;) {
		v.clear();

		for (int i = 0; i < shots; ++i) {
			FD_ZERO(&rset);
			FD_SET(0, &rset);
			timeval tv = {0, secs};
			if (select(0 + 1, &rset, NULL, NULL, &tv) != 1)
				break;

			name = "";
			if (!(cin>>name)) {
				eof = 1;
				break;
			}

			if (dns->query(name, req, qtype) >= 0)
				v.push_back(req);
		}

		if (dns->send(v) < 0)
			cerr<<dns->why()<<endl;

		for (;;) {

			if (eof) {
				r = dns->poll(2);
				if (!r)
					return 0;
			}

			r = dns->recv(res);

			if (r < 0)
				cerr<<dns->why();

			if (r == 1) {
				name = "";
				result.clear();
				if (dns->parse_response(res, name, result) <= 0)
					continue;
				for (auto i = result.begin(); i != result.end(); ++i) {
					// only print resolved IP's, no CNAME or NXDOMAIN
					if (A_only) {
						if (i->first.find("A\t") == string::npos)
							continue;
					}
					cout<<name<<"\t\t"<<i->first<<"\t"<<i->second<<endl;
				}
			} else {
				if (!eof)
					break;
			}
		}
	}

	delete dns;
	return 0;
}

