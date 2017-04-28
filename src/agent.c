/**
 * @file agent.c ICE agent
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <re.h>
#include <rew.h>
#include "reicec.h"


enum {
	COMPID = 1
};

enum {
	LAYER_ICE  =   0,
	LAYER_STUN = -10,
	LAYER_TURN = -10,
};


static void turnc_handler(int err, uint16_t scode, const char *reason,
			  const struct sa *relay_addr,
			  const struct sa *mapped_addr,
			  const struct stun_msg *msg,
			  void *arg);


static void ice_estab_handler(struct ice_candpair *pair,
			      const struct stun_msg *msg, void *arg)
{
	struct agent *ag = arg;
	(void)ag;
	(void)msg;

	re_printf("established: %H\n", trice_candpair_debug, pair);

	if (trice_checklist_iscompleted(ag->icem)) {

		re_printf("checklist completed! -- stop.\n");

		if (ag->cli->client && !ag->cli->param.wait)
			re_cancel();
	}
}


static void ice_failed_handler(int err, uint16_t scode,
			       struct ice_candpair *pair, void *arg)
{
	struct agent *ag = arg;
	(void)pair;
	(void)ag;

	re_printf("candidate-pair failed (%m %u)\n", err, scode);

	if (trice_checklist_iscompleted(ag->icem)) {

		re_printf("checklist completed! -- stop.\n");

		if (ag->cli->client && !ag->cli->param.wait)
			re_cancel();
	}
}


static uint16_t local_tcp_preference(enum ice_tcptype tcptype,
				     uint16_t other_pref)
{
	uint16_t dir_pref = 0;

	switch (tcptype) {

	case ICE_TCP_ACTIVE:  dir_pref = 6; break;
	case ICE_TCP_PASSIVE: dir_pref = 4; break;
	case ICE_TCP_SO:      dir_pref = 2; break;
	}

	return (dir_pref<<13) + other_pref;
}


static uint32_t calc_prio(enum ice_cand_type type, int proto,
			  enum ice_tcptype tcptype, int af, int turn_proto)
{
	uint16_t lpref = 0;

	switch (proto) {

	case IPPROTO_UDP:
		if (af==AF_INET6)
			lpref = turn_proto==IPPROTO_UDP ? 65535 : 65533;
		else
			lpref = turn_proto==IPPROTO_UDP ? 65534 : 65532;
		break;

	case IPPROTO_TCP:
		lpref = local_tcp_preference(tcptype, af==AF_INET6);
		break;
	}

	return ice_cand_calc_prio(type, lpref, COMPID);
}


static bool is_gathering_complete(const struct agent *ag)
{
	unsigned i;

	for (i=0; i<ag->candc; i++) {

		if (!ag->candv[i].done)
			return false;
	}

	return true;
}


static void candidate_done(struct candidate *cand)
{
	struct agent *ag = cand->ag;
	int err;

	cand->done = true;

	if (is_gathering_complete(ag)) {

		re_printf("All local candidate gathering completed"
			  " -- sending EOC\n");

		ag->local_eoc = true;

		err = control_send_message(ag->cli, "a=end-of-candidates\r\n");
		if (err) {
			re_fprintf(stderr, "failed to send EOC\n");
		}
	}
}


static void stun_mapped_handler(int err, const struct sa *map, void *arg)
{
	struct candidate *cand = arg;
	struct ice_lcand *lcand=0, *base = cand->base;
	uint32_t prio;

	if (err) {
		re_printf("STUN Request failed: (%m)\n",
			  err);
		goto out;
	}

	re_printf("adding SRFLX candidate %s.%J\n",
		  net_proto2name(base->attr.proto), map);

	prio = calc_prio(ICE_CAND_TYPE_SRFLX, base->attr.proto,
			 base->attr.tcptype, sa_af(&base->attr.addr),
			 base->attr.proto);

	err = trice_lcand_add(&lcand, base->icem, base->attr.compid,
			      base->attr.proto, prio, map,
			      &base->attr.addr, ICE_CAND_TYPE_SRFLX,
			      &base->attr.addr,
			      base->attr.tcptype, NULL, 0);
	if (err) {
		re_fprintf(stderr, "failed to add SRFLX candidate (%m)\n",
			   err);
		goto out;
	}

	err = control_send_message(cand->ag->cli, "a=candidate:%H\r\n",
				   ice_cand_attr_encode, &lcand->attr);
	if (err)
		goto out;

 out:
	candidate_done(cand);
}


static void stun_resp_handler(int err, uint16_t scode, const char *reason,
			      const struct stun_msg *msg, void *arg)
{
	struct candidate *cand = arg;
	struct stun_attr *attr = NULL;

	if (err || scode) {
		re_printf("STUN Request failed: %u %s (%m)\n",
			  scode, reason, err);
		candidate_done(cand);
		return;
	}

	attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
	if (!attr) {
		re_fprintf(stderr, "no XOR-MAPPED-ADDR in response\n");
		return;
	}

	stun_mapped_handler(err, &attr->v.sa, cand);
}


/* shared between STUN and TURN */
static void tcp_estab_handler(void *arg)
{
	struct candidate *cand = arg;
	int err;

	re_printf("TCP established to STUN/TURN-server\n");

	switch (cand->type) {

	case TYPE_STUN:
		err = stun_request(NULL, cand->ag->stun, IPPROTO_TCP,
				   cand->tc, NULL, 0, STUN_METHOD_BINDING,
				   NULL, 0, false,
				   stun_resp_handler, cand, 0);
		if (err) {
			re_printf("tcp: stun_request failed (%m)\n", err);
		}
		break;

	case TYPE_TURN:
		err = turnc_alloc(&cand->turnc, NULL, IPPROTO_TCP,
				  cand->tc, LAYER_TURN, &cand->turn_srv,
				  cand->ag->cli->param.username,
				  cand->ag->cli->param.password,
				  TURN_DEFAULT_LIFETIME, turnc_handler, cand);
		if (err) {
			re_printf("tcp: turn client: %m\n", err);
		}
		break;
	}
}


/* only used for STUN gathering */
static void process_stun(struct candidate *cand, struct mbuf *mb)
{
	struct stun_unknown_attr ua;
	struct stun_msg *msg;
	int err;

	err = stun_msg_decode(&msg, mb, &ua);
	if (err) {
		re_fprintf(stderr, "could not decode STUN message\n");
		return;
	}

	switch (stun_msg_class(msg)) {

	case STUN_CLASS_ERROR_RESP:
	case STUN_CLASS_SUCCESS_RESP:
		(void)stun_ctrans_recv(cand->ag->stun, msg, &ua);
		break;

	default:
		break;
	}

	mem_deref(msg);
}


static void handle_packet(struct candidate *cand, struct mbuf *mb)
{
	int err;

	switch (cand->type) {

	case TYPE_STUN:
		process_stun(cand, mb);
		break;

	case TYPE_TURN: {
		struct sa src;

		err = turnc_recv(cand->turnc, &src, mb);
		if (err)
			goto out;

		/* NOTE: any packets received via TURN must
		   be sent into the ICE-stack via the UDP-socket
		   of the base candidate */
		if (mbuf_get_left(mb)) {

#if 0
			/* "inject" packet into UDP-socket */
			udp_recv_helpers(cand->base->us, &src,
					 mb, cand->uh_turntcp);
#endif

			re_printf("todo: handle %zu bytes\n",
				      mbuf_get_left(mb));

			/* todo: add icem_recv() function instead ? */
		}
	}
		break;
	}

 out:
	return;
}


static void tcp_recv_handler(struct mbuf *mbx, void *arg)
{
	struct candidate *tl = arg;
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
		uint16_t typ;

		if (mbuf_get_left(tl->mb) < 4)
			break;

		/* STUN Header */
		typ = ntohs(mbuf_read_u16(tl->mb));
		len = ntohs(mbuf_read_u16(tl->mb));

		if (typ < 0x4000)
			len += STUN_HEADER_SIZE;
		else if (typ < 0x8000)
			len += 4;
		else {
			err = EBADMSG;
			goto out;
		}

		tl->mb->pos -= 4;

		if (mbuf_get_left(tl->mb) < len)
			break;

		pos = tl->mb->pos;
		end = tl->mb->end;

		tl->mb->end = pos + len;

		handle_packet(tl, tl->mb);

		/* 4 byte alignment */
		while (len & 0x03)
			++len;

		tl->mb->pos = pos + len;
		tl->mb->end = end;

		if (tl->mb->pos >= tl->mb->end) {
			tl->mb = mem_deref(tl->mb);
			break;
		}
	}

 out:
	if (err) {
		re_printf("tcp recv error (%m)\n", err);
	}
}


static void tcp_close_handler(int err, void *arg)
{
	struct candidate *cand = arg;

	re_printf("TCP-connection to STUN-server closed (%m)\n", err);

	cand->tc = mem_deref(cand->tc);

	candidate_done(cand);
}


static int gather_srflx2(struct candidate *cand, int proto)
{
	struct ice_lcand *base = cand->base;
	int err;

	switch (proto) {

	case IPPROTO_UDP:
		err = stun_keepalive_alloc(&cand->ska, proto,
					   base->us, LAYER_STUN,
					   &cand->stun_srv,
					   NULL,
					   stun_mapped_handler, cand);
		if (err) {
			re_printf("stun_request failed (%m)\n", err);
		}
		stun_keepalive_enable(cand->ska, 25);
		break;

	case IPPROTO_TCP:
		/* for TCP we must connect FROM the locally bound
		   socket (either passive or S-O) */

		re_printf("SRFLX tcp connecting.. %J -> %J\n",
			  &base->attr.addr, &cand->stun_srv);

		err = tcp_conn_alloc(&cand->tc, &cand->stun_srv,
				     tcp_estab_handler, tcp_recv_handler,
				     tcp_close_handler, cand);
		if (err) {
			re_fprintf(stderr, "tcp_conn_alloc failed (%m)\n",
				   err);
			return err;
		}

		err = tcp_conn_bind(cand->tc, &base->attr.addr);
		if (err) {
			re_fprintf(stderr, "tcp_conn_bind to %J failed"
				   " (%m)\n",
				   &base->attr.addr, err);
			return err;
		}

		err = tcp_conn_connect(cand->tc, &cand->stun_srv);
		if (err) {
			re_fprintf(stderr, "tcp_conn_connect to %J failed"
				   " (%m)\n",
				   err, &cand->stun_srv);
			return err;
		}

		break;

	default:
		return EPROTONOSUPPORT;
	}

	return 0;
}


static void turnc_perm_handler(void *arg)
{
	struct ice_rcand *rcand = arg;

	re_printf("turn permission OK (remote = %j)\n", &rcand->attr.addr);
}


/* add TURN permission to all known remotes */
static int candidate_add_permissions(struct candidate *candidate)
{
	struct le *le;
	struct trice *icem;
	int err = 0;

	if (candidate->type != TYPE_TURN || !candidate->turn_ok)
		return 0;

	icem = candidate->ag->icem;
	for (le = list_head(trice_rcandl(icem)); le; le = le->next) {

		struct ice_rcand *rcand = le->data;
		struct ice_lcand *base = candidate->base;

		if (rcand->attr.proto == IPPROTO_UDP &&
		    rcand->attr.compid == base->attr.compid &&
		    sa_af(&rcand->attr.addr) == sa_af(&base->attr.addr)) {

			err |= turnc_add_perm(candidate->turnc,
					      &rcand->attr.addr,
					      turnc_perm_handler, rcand);
		}
	}

	return err;
}


/* all outgoing UDP-packets must be sent via
 * the TCP-connection to the TURN server
 */
static bool turntcp_send_handler(int *err, struct sa *dst,
				 struct mbuf *mb, void *arg)
{
	struct candidate *cand = arg;

#if 0
	re_printf("   ~~~~ turntcp: SEND [presz=%zu] (%zu bytes to %J)\n",
		  mb->pos, mbuf_get_left(mb), dst);
#endif

	*err = turnc_send(cand->turnc, dst, mb);

	return true;
}


static void turnc_handler(int err, uint16_t scode, const char *reason,
			  const struct sa *relay_addr,
			  const struct sa *mapped_addr,
			  const struct stun_msg *msg,
			  void *arg)
{
	struct candidate *cand = arg;
	struct ice_lcand *lcand_relay=0, *lcand_srflx=0, *base = cand->base;
	uint32_t prio;

	if (err || scode) {
		re_printf("TURN client error: %u %s (%m)\n",
			  scode, reason, err);
		goto out;
	}

	/* check if the relayed address is of the same Address Family
	 * as the base candidate */
	if (sa_af(relay_addr) != sa_af(&base->attr.addr)) {
		re_printf("could not use RELAY address (AF mismatch)\n");
		goto out;
	}

	if (stun_msg_method(msg) == STUN_METHOD_ALLOCATE) {
		re_printf("TURN allocation okay (turn-proto=%s)\n",
			  net_proto2name(cand->turn_proto));
		cand->turn_ok = true;
	}

	/* RELAY */

	re_printf("adding RELAY candidate %s.%J\n",
		  net_proto2name(base->attr.proto), relay_addr);

	prio = calc_prio(ICE_CAND_TYPE_RELAY, base->attr.proto,
			 base->attr.tcptype, sa_af(&base->attr.addr),
			 cand->turn_proto);

	err = trice_lcand_add(&lcand_relay, base->icem,
			      base->attr.compid,
			      base->attr.proto, prio, relay_addr,
			      relay_addr, ICE_CAND_TYPE_RELAY,
			      mapped_addr,
			      base->attr.tcptype, base->us,
			      LAYER_ICE);
	if (err) {
		re_fprintf(stderr, "failed to add RELAY candidate (%m)\n",
			   err);
		goto out;
	}

	if (cand->turn_proto == IPPROTO_TCP) {

		/* NOTE: this is needed to snap up outgoing UDP-packets */

		err = udp_register_helper(&cand->uh_turntcp,
					  lcand_relay->us,
					  LAYER_TURN,
					  turntcp_send_handler,
					  NULL,
					  cand);
		if (err) {
			re_printf("helper error\n");
			goto out;
		}
	}

	/* SRFLX */
	if (cand->turn_proto == base->attr.proto) {
		re_printf("adding SRFLX candidate %s.%J\n",
			  net_proto2name(base->attr.proto), mapped_addr);

		prio = calc_prio(ICE_CAND_TYPE_SRFLX, base->attr.proto,
				 base->attr.tcptype, sa_af(&base->attr.addr),
				 base->attr.proto);

		err = trice_lcand_add(&lcand_srflx, base->icem,
				      base->attr.compid,
				      base->attr.proto, prio,
				      mapped_addr, &base->attr.addr,
				      ICE_CAND_TYPE_SRFLX,
				      &base->attr.addr,
				      base->attr.tcptype,
				      NULL, LAYER_ICE);
		if (err) {
			re_fprintf(stderr, "failed to add SRFLX"
				   " candidate (%m)\n",
				   err);
			goto out;
		}
	}

	err = control_send_message(cand->ag->cli,
				   "a=candidate:%H\r\n"
				   "a=candidate:%H\r\n"
				   ,
				   ice_cand_attr_encode, &lcand_relay->attr,
				   ice_cand_attr_encode,
				   lcand_srflx ? &lcand_srflx->attr : 0);
	if (err)
		goto out;

	candidate_add_permissions(cand);

 out:
	candidate_done(cand);
}


static int gather_relay2(struct candidate *cand, int turn_proto)
{
	struct ice_lcand *base = cand->base;
	int err;

	switch (turn_proto) {

	case IPPROTO_UDP:

		/* the TURN-client must be created using the UDP-socket
		 * of the base candidate
		 */
		err = turnc_alloc(&cand->turnc, NULL, turn_proto,
				  base->us, LAYER_TURN, &cand->turn_srv,
				  cand->ag->cli->param.username,
				  cand->ag->cli->param.password,
				  TURN_DEFAULT_LIFETIME, turnc_handler, cand);
		if (err) {
			re_printf("turn client: %m\n", err);
		}
		break;

	case IPPROTO_TCP:

		re_printf("TURN-TCP -- connecting to %J ..\n",
			  &cand->turn_srv);

		/* NOTE: we are connecting _from_ an ephemeral port,
		 *       since we might have Zero TCP-candidates
		 */
		err = tcp_connect(&cand->tc, &cand->turn_srv,
				  tcp_estab_handler, tcp_recv_handler,
				  tcp_close_handler, cand);
		if (err) {
			re_printf("tcp_connect error (%m)\n", err);
			return err;
		}
		break;

	default:
		return EPROTONOSUPPORT;
	}

	return 0;
}


static void stun_dns_handler(int err, const struct sa *srv, void *arg)
{
	struct candidate *cand = arg;

	if (err) {
		re_fprintf(stderr, "could not resolve STUN server (%m)\n",
			   err);
		candidate_done(cand);
		return;
	}

	switch (cand->type) {

	case TYPE_STUN:
		re_printf("resolved STUN-server (%J)\n", srv);
		cand->stun_srv = *srv;
		gather_srflx2(cand, cand->base->attr.proto);
		break;

	case TYPE_TURN:
		re_printf("resolved TURN-server (%J)\n", srv);
		cand->turn_srv = *srv;
		gather_relay2(cand, cand->turn_proto);
		break;

	default:
		re_printf("unknown type\n");
		break;
	}
}


static int gather_srflx(struct agent *ag, struct ice_lcand *base, int proto)
{
	struct candidate *cand = &ag->candv[ag->candc++];
	const char *proto_name = "";
	int err;

	if (ag->candc >= ARRAY_SIZE(ag->candv))
		return ENOMEM;

	cand->ag = ag;
	cand->base = base;
	cand->type = TYPE_STUN;

	switch (proto) {

	case IPPROTO_UDP:
		proto_name = stun_proto_udp;
		break;
	case IPPROTO_TCP:
		proto_name = stun_proto_tcp;
		break;
	}

	re_printf("resolving %s..\n", ag->cli->param.stun_server);

	err = stun_server_discover(&cand->stun_dns, cand->ag->cli->dnsc,
				   stun_usage_binding, proto_name,
				   sa_af(&base->attr.addr),
				   ag->cli->param.stun_server, 0,
				   stun_dns_handler, cand);
	if (err) {
		re_fprintf(stderr, "stun_server_discover failed (%m)\n",
			   err);
		return err;
	}

	return 0;
}


static int gather_relay(struct agent *ag, struct ice_lcand *base,
			int turn_proto)
{
	struct candidate *cand = &ag->candv[ag->candc++];
	const char *proto_name = "";
	int err;

	if (ag->candc >= ARRAY_SIZE(ag->candv))
		return ENOMEM;

	cand->ag = ag;
	cand->base = base;
	cand->type = TYPE_TURN;
	cand->turn_proto = turn_proto;

	switch (turn_proto) {

	case IPPROTO_UDP:
		proto_name = stun_proto_udp;
		break;

	case IPPROTO_TCP:
		proto_name = stun_proto_tcp;
		break;
	}

	re_printf("resolving TURN-server '%s' for %s..\n",
		  ag->cli->param.turn_server, proto_name);

	err = stun_server_discover(&cand->stun_dns, cand->ag->cli->dnsc,
				   stun_usage_relay, proto_name,
				   sa_af(&base->attr.addr),
				   ag->cli->param.turn_server, 0,
				   stun_dns_handler, cand);
	if (err) {
		re_fprintf(stderr, "stun_server_discover failed (%m)\n",
			   err);
		return err;
	}

	return 0;
}


static int add_candidate(struct agent *ag, const struct sa *addr,
			 int proto, enum ice_tcptype tcptype,
			 const char *ifname)
{
	struct ice_lcand *lcand;
	uint32_t prio;
	int err;

	prio = calc_prio(ICE_CAND_TYPE_HOST, proto, tcptype, sa_af(addr),
			 proto);

	err = trice_lcand_add(&lcand, ag->icem, COMPID, proto,
			      prio, addr, NULL, ICE_CAND_TYPE_HOST, NULL,
			      tcptype, NULL, LAYER_ICE);
	if (err) {
		re_fprintf(stderr, "failed to add local candidate (%m)\n",
			   err);
		return err;
	}

	str_ncpy(lcand->ifname, ifname, sizeof(lcand->ifname));

	err = control_send_message(ag->cli, "a=candidate:%H\r\n",
				   ice_cand_attr_encode, &lcand->attr);
	if (err)
		return err;

	/* gather SRFLX candidates */
	if (ag->cli->param.stun_server) {

		if (proto == IPPROTO_UDP ||
		    (proto == IPPROTO_TCP && tcptype != ICE_TCP_ACTIVE)) {

			gather_srflx(ag, lcand, proto);
		}
	}

	/* gather RELAY candidates, NOTE IPv4 only */
	if (ag->cli->param.turn_server) {
		if (proto == IPPROTO_UDP && sa_af(addr)==AF_INET) {

			gather_relay(ag, lcand, IPPROTO_UDP);
			gather_relay(ag, lcand, IPPROTO_TCP);
		}
	}

	return err;
}


static bool interface_find(const struct agent *ag, const struct sa *addr)
{
	unsigned i;

	for (i=0; i<ag->interfacec; i++) {

		if (sa_cmp(addr, &ag->interfacev[i], SA_ADDR))
			return true;
	}

	return false;
}


static bool interface_handler(const char *ifname, const struct sa *addr,
			      void *arg)
{
	struct agent *ag = arg;
	int err = 0;

	/* Skip loopback and link-local addresses */
	if (ag->cli->param.skip_local) {

		if (sa_is_loopback(addr) || sa_is_linklocal(addr))
			return false;
	}

	if (str_isset(ag->cli->param.ifname) &&
	    str_casecmp(ag->cli->param.ifname, ifname)) {
		return false;
	}

	switch (sa_af(addr)) {

	case AF_INET:
		if (!ag->cli->param.use_ipv4)
			return false;
		break;

	case AF_INET6:
		if (!ag->cli->param.use_ipv6)
			return false;
		break;
	}

	/* NOTE: on some machines an interface is listed twice. */
	if (interface_find(ag, addr)) {
		re_printf("ignoring duplicated interface (%s %j)\n",
			  ifname, addr);
		return false;
	}
	ag->interfacev[ag->interfacec++] = *addr;

	re_printf("interface: %s %j\n", ifname, addr);

	if (ag->cli->param.use_udp)
		err |= add_candidate(ag, addr, IPPROTO_UDP, 0, ifname);
	if (ag->cli->param.use_tcp) {
		err |= add_candidate(ag, addr, IPPROTO_TCP, ICE_TCP_SO,
				     ifname);
		err |= add_candidate(ag, addr, IPPROTO_TCP,
			     ag->client ? ICE_TCP_ACTIVE : ICE_TCP_PASSIVE,
			     ifname);
	}

	return err != 0;
}


static void destructor(void *arg)
{
	struct agent *ag = arg;
	unsigned i;

	if (ag->icem)
		re_printf("%H\n", trice_debug, ag->icem);

	for (i=0; i<ag->candc; i++) {
		mem_deref(ag->candv[i].uh_turntcp);
		mem_deref(ag->candv[i].ska);
		mem_deref(ag->candv[i].tc);
		mem_deref(ag->candv[i].mb);
		mem_deref(ag->candv[i].stun_dns);
		mem_deref(ag->candv[i].turnc);     /* deref before ICEM */
	}

	mem_deref(ag->icem);
	mem_deref(ag->stun);
}


int agent_alloc(struct agent **agp, struct reicec *cli,
		const struct trice_conf *conf)
{
	struct agent *ag;
	enum ice_role role;
	int err = 0;

	ag = mem_zalloc(sizeof(*ag), destructor);
	if (!ag)
		return ENOMEM;

	ag->cli = cli;
	ag->client = cli->client;
	rand_str(ag->lufrag, sizeof(ag->lufrag));
	rand_str(ag->lpwd, sizeof(ag->lpwd));

	role = cli->client ? ICE_ROLE_CONTROLLING : ICE_ROLE_CONTROLLED;

	err = trice_alloc(&ag->icem, conf, role, ag->lufrag, ag->lpwd);
	if (err)
		goto out;

	err = stun_alloc(&ag->stun, NULL, NULL, NULL);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(ag);
	else
		*agp = ag;

	return err;
}


void agent_gather(struct agent *ag)
{
	int err;

	if (!ag)
		return;

	net_if_apply(interface_handler, ag);

	re_printf("HOST gathering complete (interfaces = %u)\n",
		  ag->interfacec);

	if (is_gathering_complete(ag)) {

		re_printf("local candidate gathering completed"
			  " -- sending EOC\n");

		ag->local_eoc = true;

		err = control_send_message(ag->cli, "a=end-of-candidates\r\n");
		if (err) {
			re_fprintf(stderr, "failed to send EOC\n");
		}
	}
}


static int agent_rcand_decode_add(struct trice *icem, const char *val)
{
	struct ice_cand_attr rcand;
	int err;

	err = ice_cand_attr_decode(&rcand, val);
	if (err)
		return err;

	/* add only if not exist */
	return trice_rcand_add(NULL, icem, rcand.compid,
			       rcand.foundation, rcand.proto,
			       rcand.prio, &rcand.addr,
			       rcand.type, rcand.tcptype);
}


int agent_process_remote_attr(struct agent *ag,
			      const char *name, const char *value)
{
	int err = 0;

	if (!ag || !name)
		return EINVAL;

	if (0 == str_casecmp(name, "ice-ufrag")) {
		ag->rufrag = true;
		err = trice_set_remote_ufrag(ag->icem, value);
	}
	else if (0 == str_casecmp(name, "ice-pwd")) {
		ag->rpwd = true;
		err = trice_set_remote_pwd(ag->icem, value);
	}
	else if (0 == str_casecmp(name, "candidate")) {
		unsigned i;

		err = agent_rcand_decode_add(ag->icem, value);

		for (i=0; i<ag->candc; i++)
			candidate_add_permissions(&ag->candv[i]);
	}
	else if (0 == str_casecmp(name, "end-of-candidates")) {
		re_printf("got end-of-candidates from remote\n");
		ag->remote_eoc = true;
	}
	else {
		re_printf("attribute ignored: %s\n", name);
	}

	if (err) {
		re_printf("remote attr error (%m)\n", err);
		return err;
	}

	if (ag->rufrag && ag->rpwd && ag->cli->param.run_checklist
	    && !list_isempty(trice_rcandl(ag->icem))
	    && !trice_checklist_isrunning(ag->icem)) {

		re_printf("starting ICE checklist with pacing interval"
			  " %u milliseconds..\n",
			  ag->cli->param.pacing_interval);

		err = trice_checklist_start(ag->icem, NULL,
					    ag->cli->param.pacing_interval,
					    true,
					    ice_estab_handler,
					    ice_failed_handler, ag);
		if (err) {
			re_fprintf(stderr, "could not start checklist (%m)\n",
				   err);
		}
	}

	return 0;
}
