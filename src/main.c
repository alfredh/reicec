/**
 * @file main.c Main application code
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <re.h>
#include <rew.h>
#include "reicec.h"


/* TODO:
 *
 * ok - add SRFLX candidates
 * ok - add RELAY candidates (via UDP)
 * ok - add RELAY candidates (via TCP)
 * ok - add TCP candidates
 *
 *    - add a traffic-generator/RTT for each working candpair
 *
 *    - ignore duplicated interfaces
 *    - add a generic STUN/TURN de-framing mechanism
 */


#define PORT 9000
#define MSG_MAX_LENGTH 4096


static struct trice_conf conf = {0, 0, 1};


static void destructor(void *arg)
{
	struct reicec *cli = arg;

	mem_deref(cli->mb);
	mem_deref(cli->ag);
	mem_deref(cli->tc);
	mem_deref(cli->ts);
	mem_deref(cli->dnsc);
}


static void tcp_estab_handler(void *arg)
{
	struct reicec *cli = arg;
	int err;

	re_printf("Control channel established\n");

	err = agent_alloc(&cli->ag, cli, &conf);
	if (err) {
		re_fprintf(stderr, "failed to allocate agent (%m)\n", err);
		return;
	}

	err = control_send_message(cli,
				   "a=ice-ufrag:%s\r\n"
				   "a=ice-pwd:%s\r\n",
				   cli->ag->lufrag, cli->ag->lpwd);
	if (err) {
		re_fprintf(stderr, "failed to send local ICE credentials"
			   " (%m)\n", err);
	}

	agent_gather(cli->ag);
}


static void control_recv_message(struct reicec *cli, struct mbuf *mb)
{
	struct pl pl;

	pl_set_mbuf(&pl, mb);

	while (pl.l) {
		struct pl nam, val;
		char name[256], value[256];

		if (0==re_regex(pl.p, pl.l, "a=[^:]+:[^\r\n]+",
				&nam, &val)) {

			pl_strcpy(&nam, name, sizeof(name));
			pl_strcpy(&val, value, sizeof(value));

			pl_advance(&pl, 2 + nam.l + 1 + val.l + 2);

			agent_process_remote_attr(cli->ag, name, value);
		}
		else if (0==re_regex(pl.p, pl.l, "a=[^\r\n]+",
				&nam)) {

			pl_strcpy(&nam, name, sizeof(name));
			pl_advance(&pl, 2 + nam.l + 2);

			agent_process_remote_attr(cli->ag, name, NULL);
		}
		else {
			re_fprintf(stderr, "could not decode attribute"
				   " (%r)\n", &pl);
			break;
		}
	}
}


static void tcp_recv_handler(struct mbuf *mbx, void *arg)
{
	struct reicec *tl = arg;
	int err = 0;

	if (tl->mb) {
		size_t pos;

		pos = tl->mb->pos;

		tl->mb->pos = tl->mb->end;

		err = mbuf_write_mem(tl->mb, mbuf_buf(mbx),
				     mbuf_get_left(mbx));
		if (err)
			goto out;

		tl->mb->pos = pos;
	}
	else {
		tl->mb = mem_ref(mbx);
	}

	for (;;) {

		size_t len, pos, end;

		if (mbuf_get_left(tl->mb) < 4)
			break;

		len = ntohs(mbuf_read_u16(tl->mb));

		if (len > MSG_MAX_LENGTH) {
			re_printf("recv: corrupt framing (len=%zu bytes)\n",
				  len);
			err = EPROTO;
			goto out;
		}
		if (mbuf_get_left(tl->mb) < len) {
			tl->mb->pos -= 2;
			break;
		}

		pos = tl->mb->pos;
		end = tl->mb->end;

		tl->mb->end = pos + len;

		control_recv_message(tl, tl->mb);

		tl->mb->pos = pos + len;
		tl->mb->end = end;

		if (tl->mb->pos >= tl->mb->end) {
			tl->mb = mem_deref(tl->mb);
			break;
		}
	}

 out:
	if (err) {
		re_printf("control-channel error (%m)\n", err);
		tl->tc = mem_deref(tl->tc);
		re_cancel();
	}
}


static void tcp_close_handler(int err, void *arg)
{
	struct reicec *cli = arg;

	re_printf("Control channel closed (%m)\n", err);

	cli->tc = mem_deref(cli->tc);
	cli->ag = mem_deref(cli->ag);

	if (cli->client)
		re_cancel();
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct reicec *cli = arg;
	int err;
	(void)peer;

	if (cli->tc) {
		tcp_reject(cli->ts);
	}
	else {
		err = tcp_accept(&cli->tc, cli->ts, tcp_estab_handler,
				 tcp_recv_handler, tcp_close_handler, cli);
		if (err) {
			re_fprintf(stderr, "tcp accept failed (%m)\n", err);
			tcp_reject(cli->ts);
		}
	}
}


int control_send_message(struct reicec *cli, const char *msg, ...)
{
	struct mbuf *mb;
	size_t len;
	va_list ap;
	int err;

	if (!cli || !msg)
		return EINVAL;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	mb->pos = 2;

	va_start(ap, msg);
	err = mbuf_vprintf(mb, msg, ap);
	va_end(ap);
	if (err)
		goto out;

	len = mb->end - 2;
	if (len > MSG_MAX_LENGTH) {
		re_printf("message too large\n");
		err = EOVERFLOW;
		goto out;
	}

	mb->pos = 0;
	err = mbuf_write_u16(mb, htons(len));

	if (err)
		goto out;

	mb->pos = 0;
	err = tcp_send(cli->tc, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);
	return err;
}


static int reicec_alloc(struct reicec **clip, const struct param *param,
			bool client, const char *peer)
{
	struct reicec *cli;
	int err = 0;

	if (!clip || !param)
		return EINVAL;

	cli = mem_zalloc(sizeof(*cli), destructor);
	if (!cli)
		return ENOMEM;

	cli->param = *param;
	cli->client = client;

	if (client) {
		struct sa paddr;

		err = sa_set_str(&paddr, peer, PORT);
		if (err) {
			re_fprintf(stderr, "invalid address (%s)\n", peer);
			goto out;
		}

		re_printf("connecting to %J..\n", &paddr);

		err = tcp_connect(&cli->tc, &paddr, tcp_estab_handler,
				  tcp_recv_handler, tcp_close_handler, cli);
		if (err) {
			re_fprintf(stderr, "tcp connect to %J failed (%m)\n",
				   &paddr, err);
			goto out;
		}
	}
	else {
		struct sa laddr;

		sa_set_str(&laddr, "::", PORT);

		err = tcp_listen(&cli->ts, &laddr, tcp_conn_handler, cli);
		if (err) {
			re_fprintf(stderr, "tcp listen on %J failed (%m)\n",
				   &laddr, err);
			goto out;
		}

		re_printf("listening on TCP %J\n", &laddr);
	}

 out:
	if (err)
		mem_deref(cli);
	else
		*clip = cli;

	return err;
}


static int dns_init(struct dnsc **dnsc, char *domain, uint32_t dsize)
{
	struct sa nsv[8];
	uint32_t nsn;
	int err;

	nsn = ARRAY_SIZE(nsv);

	err = dns_srv_get(domain, dsize, nsv, &nsn);
	if (err) {
		(void)re_fprintf(stderr, "dns_srv_get: %s\n", strerror(err));
		goto out;
	}

	err = dnsc_alloc(dnsc, NULL, nsv, nsn);
	if (err) {
		(void)re_fprintf(stderr, "dnsc_alloc: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;
}


static void signal_handler(int signum)
{
	(void)signum;

	re_fprintf(stderr, "terminated on signal %d\n", signum);

	re_cancel();
}


static void usage(void)
{
	re_fprintf(stderr,
		   "Usage: reicec [-s|-c <host>] [options]\n"
		   "       reicec [-h]\n"
		   "\n"
		   "Client/Server:\n"
		   "\t-c <host>   Run in client mode, connecting to <host>\n"
		   "\t-s          Run in Server mode\n"
		   "\n"
		   "Candidates options:\n"
		   "\t-u          Enable UDP candidates\n"
		   "\t-t          Enable TCP candidates\n"
		   "\t-4          Enable IPv4 candidates\n"
		   "\t-6          Enable IPv6 candidates\n"
		   "\t-i <if>     Bound to only this interface\n"
		   "\t-S <STUN>   Enable SRFLX from this STUN-server\n"
		   "\t-T <TURN>   Enable RELAY/SRFLX from this TURN-server\n"
		   "\t-U <user>   TURN username\n"
		   "\t-P <pass>   TURN password\n"
		   "\t-L          Include local and link-local addresses\n"
		   "\n"
		   "Miscellaneous:\n"
		   "\t-C          Force running ICE checklist\n"
		   "\t-p          Checklist pacing interval (milliseconds)\n"
		   "\t-D          Enable ICE debugging\n"
		   "\t-X          Enable ICE packet tracing\n"
		   "\t-h          Print this message and quit\n"
		   "\t-w          Wait forever, do not quit\n"
		   "\n"
		   "All possible candidates are enabled by default\n"
		   );

}


int main(int argc, char *argv[])
{
	struct reicec *reicec = NULL;
	const char *peer = NULL;
	struct param param = {
		.username = "",
		.password = "",
		.use_udp = true,
		.use_tcp = true,
		.use_ipv4 = true,
		.use_ipv6 = true,
		.pacing_interval = 20,
		.skip_local = true,
	};
	bool client = false, server = false;
	bool udp = false, tcp = false;
	bool ipv4 = false, ipv6 = false;
	int err = 0;

	for (;;) {

		const int c = getopt(argc, argv,
				     "46c:CDi:p:sS:tT:huXU:P:wL");
		if (0 > c)
			break;

		switch (c) {

		case '4':
			ipv4 = true;
			break;

		case '6':
			ipv6 = true;
			break;

		case 'c':
			peer = optarg;
			client = true;
			break;

		case 'C':
			param.run_checklist = true;
			break;

		case 'D':
			conf.debug = true;
			break;

		case 'i':
			param.ifname = optarg;
			break;

		case 'L':
			param.skip_local = false;
			break;

		case 'p':
			param.pacing_interval = atoi(optarg);
			break;

		case 'P':
			param.password = optarg;
			break;

		case 's':
			server = true;
			break;

		case 'S':
			param.stun_server = optarg;
			re_printf("stun-server: %s\n", param.stun_server);
			break;

		case 't':
			tcp = true;
			break;

		case 'T':
			param.turn_server = optarg;
			re_printf("TURN-server: %s\n", param.turn_server);
			break;

		case 'X':
			conf.trace = true;
			break;

		case 'u':
			udp = true;
			break;

		case 'U':
			param.username = optarg;
			break;

		case 'w':
			param.wait = true;
			break;

		case '?':
		default:
			err = EINVAL;
			/*@fallthrough@*/
		case 'h':
			usage();
			return err;
		}
	}

	if (argc < 1) {
		usage();
		return -EINVAL;
	}

	if (!client && !server) {
		re_fprintf(stderr, "please specify either -c <host> or -s\n");
		return EINVAL;
	}
	else if (client && server) {
		re_fprintf(stderr, "both -c and -s not possible.\n");
		return EINVAL;
	}

	if (ipv4 || ipv6) {
		param.use_ipv4 = ipv4;
		param.use_ipv6 = ipv6;
	}
	if (udp || tcp) {
		param.use_udp = udp;
		param.use_tcp = tcp;
	}
	if (client)
		param.run_checklist = true;

	err = libre_init();
	if (err) {
		(void)re_fprintf(stderr, "libre_init: %m\n", err);
		goto out;
	}

	(void)sys_coredump_set(true);

	err = reicec_alloc(&reicec, &param, client, peer);
	if (err) {
		(void)re_fprintf(stderr, "reicec alloc: %m\n", err);
		goto out;
	}

	err = dns_init(&reicec->dnsc, NULL, 0);
	if (err) {
		(void)re_fprintf(stderr, "dnsinit: %m\n", err);
		goto out;
	}

	re_printf("ICE agent running in %s-mode\n",
		  client ? "client" : "server");

	(void)re_main(signal_handler);

	re_printf("Bye for now\n");

 out:
	mem_deref(reicec);

	libre_close();
	mem_debug();

	return err;
}
