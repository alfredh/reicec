/**
 * @file reicec.h  Internal interface to ICE client
 *
 * Copyright (C) 2010 - 2015 Alfred E. Heggestad
 */


enum type {
	TYPE_STUN,
	TYPE_TURN
};

struct candidate {
	struct ice_lcand *base;
	struct agent *ag;
	struct stun_keepalive *ska;
	struct stun_dns *stun_dns;
	struct sa stun_srv;
	struct sa turn_srv;
	enum type type;
	struct turnc *turnc;
	int turn_proto;
	bool turn_ok;
	struct udp_helper *uh_turntcp;

	/* TCP-transport with re-assembly */
	struct tcp_conn *tc;
	struct mbuf *mb;

	bool done;  /* done; okay or failed */
};

struct agent {
	struct reicec *cli;  /* pointer to parent */
	struct trice_conf conf;
	struct trice *icem;
	struct stun *stun;
	char lufrag[8];
	char lpwd[24];
	bool client;
	bool rufrag;
	bool rpwd;

	struct candidate candv[32];
	size_t candc;

	struct sa interfacev[32];
	size_t interfacec;

	bool local_eoc;
	bool remote_eoc;

	struct ice_candpair *selected_pair;
};


int agent_alloc(struct agent **agp, struct reicec *cli,
		const struct trice_conf *conf);
void agent_gather(struct agent *ag);
int agent_process_remote_attr(struct agent *ag, const char *name,
			      const char *value);


struct param {
	const char *stun_server;
	const char *turn_server;
	const char *ifname;
	const char *username;
	const char *password;
	uint32_t pacing_interval;
	bool run_checklist;
	bool use_udp;
	bool use_tcp;
	bool use_ipv4;
	bool use_ipv6;
	bool wait;
	bool skip_local;
};

struct reicec {
	struct param param;
	struct dnsc *dnsc;
	struct tcp_conn *tc;
	struct tcp_sock *ts;
	struct agent *ag;
	struct mbuf *mb;
	bool client;
};

int control_send_message(struct reicec *cli, const char *msg, ...);
