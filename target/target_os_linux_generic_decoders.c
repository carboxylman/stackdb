
/*
 * We need type and value decoders.  Sometimes the stringification of a
 * type is always the same no matter the context; sometimes the context
 * (i.e., additional argument values of a functions) determines the
 * stringification.
 */

#include <target_api.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/un.h>

struct os_linux_generic_decoder_data {
    struct bsymbol *sockaddr_type;
    struct bsymbol *sockaddr_un_type;
    struct bsymbol *sockaddr_in_type;
    struct bsymbol *sockaddr_in6_type;
    struct bsymbol *msghdr_type;
};

int os_linux_msghdr_snprintf(struct target *target,void *_data,
			     struct value *value,char *buf,int buflen) {
    struct os_linux_generic_decoder_data *data =
	(struct os_linux_generic_decoder_data *)_data;

    if (!data) {
	errno = EINVAL;
	return -1;
    }

    return -1;
}

int os_linux_sockaddr_snprintf(struct target *target,void *_data,
			       struct value *value,char *buf,int buflen) {
    struct os_linux_generic_decoder_data *data =
	(struct os_linux_generic_decoder_data *)_data;
    struct value *clone;
    struct value *v;
    unum_t family;
    int nrc = 0;
    unsigned short port;
    uint32_t flowinfo;
    uint32_t scopeid;
    struct in_addr addr;
    struct in6_addr addr6;
    char addrstr[INET_ADDRSTRLEN];

    if (!data) {
	errno = EINVAL;
	return -1;
    }

#define Lsnprintf(...)							\
    snprintf((buf != NULL) ? buf + nrc : NULL,(buflen != 0) ? buflen - nrc : 0,	\
	     ## __VA_ARGS__)

    v = target_load_value_member(target,NULL,value,"sa_family",NULL,0);
    if (!v)
	return -1;
    family = v_unum(v);
    value_free(v);

    if (family == AF_UNIX && data->sockaddr_un_type) {
	clone = value_reload_as_type(value,data->sockaddr_un_type,0);
	if (!clone)
	    return -1;
	v = target_load_value_member(target,NULL,clone,"sun_path",NULL,0);
	if (!v) {
	    value_free(clone);
	    return -1;
	}
	/*
	 * Handle sun_path specially because if abstract unix socket,
	 * then the first byte is \0 , then the real abstract path name
	 * follows.
	 */
	if (v->bufsiz > 1 && v->buf[0] == '\0')
	    nrc = Lsnprintf("{ .sun_family = AF_UNIX, .sun_path = \"@%s\" }",
			    &(v->buf[1]));
	else
	    nrc = Lsnprintf("{ .sun_family = AF_UNIX, .sun_path = \"%s\" }",
			    v->buf);
	value_free(v);
	value_free(clone);
	return nrc;
    }
    else if (family == AF_INET) {
	clone = value_reload_as_type(value,data->sockaddr_in_type,0);
	if (!clone)
	    return -1;
	v = target_load_value_member(target,NULL,clone,"sin_port",NULL,0);
	if (!v) {
	    value_free(clone);
	    return -1;
	}
	port = ntohs((uint16_t)v_unum(v));
	value_free(v);
	v = target_load_value_member(target,NULL,clone,"sin_addr.s_addr",".",0);
	if (!v) {
	    value_free(clone);
	    return -1;
	}
	addr.s_addr = (uint32_t)v_unum(v);
	inet_ntop(AF_INET,&addr,addrstr,sizeof(addrstr));
	value_free(v);
	nrc = Lsnprintf("{ .sin_family = AF_INET, .sin_port = %hu, .sin_addr = { .s_addr = \"%s\" } }",
			port,addrstr);
	value_free(clone);
	return nrc;
    }
    else if (family == AF_INET6) {
	clone = value_reload_as_type(value,data->sockaddr_in6_type,0);
	if (!clone)
	    return -1;
	v = target_load_value_member(target,NULL,clone,"sin6_port",NULL,0);
	if (!v) {
	    verror("could not load sin6_port");
	    value_free(clone);
	    return -1;
	}
	port = ntohs((uint16_t)v_unum(v));
	value_free(v);
	v = target_load_value_member(target,NULL,clone,"sin6_flowinfo",NULL,0);
	if (!v) {
	    verror("could not load sin6_flowinfo");
	    value_free(clone);
	    return -1;
	}
	flowinfo = ntohl((uint32_t)v_unum(v));
	value_free(v);
	v = target_load_value_member(target,NULL,clone,"sin6_addr",".",0);
	if (!v) {
	    verror("could not load sin6_addr");
	    value_free(clone);
	    return -1;
	}
	memcpy(&addr6.s6_addr,v->buf,
	       ((unsigned)v->bufsiz > sizeof(addr6.s6_addr)) ? sizeof(addr6.s6_addr) : (unsigned)v->bufsiz);
	inet_ntop(AF_INET6,&addr6,addrstr,sizeof(addrstr));
	value_free(v);
	v = target_load_value_member(target,NULL,clone,"sin6_scope_id",NULL,0);
	if (!v) {
	    verror("could not load sin6_scope_id");
	    value_free(clone);
	    return -1;
	}
	scopeid = ntohl((uint32_t)v_unum(v));
	value_free(v);
	nrc = Lsnprintf("{ .sin6_family = AF_INET6, .sin6_port = %hu, .sin6_flowinfo = %u, .sin6_addr = { .s6_addr = \"%s\" }, .sin6_scope_id = %u }",
			port,flowinfo,addrstr,scopeid);
	value_free(clone);
	return nrc;
    }
    else {
	return -1;
    }
}

void *os_linux_generic_decoder_lib_bind(struct target_decoder_binding *tdb) {
    struct os_linux_generic_decoder_data *data;
    struct target *target = tdb->target;

    data = (struct os_linux_generic_decoder_data *)calloc(1,sizeof(*data));

    data->sockaddr_type =
	target_lookup_sym(target,"struct sockaddr",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    data->sockaddr_un_type =
	target_lookup_sym(target,"struct sockaddr_un",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    data->sockaddr_in_type =
	target_lookup_sym(target,"struct sockaddr_in",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    data->sockaddr_in6_type =
	target_lookup_sym(target,"struct sockaddr_in6",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    data->msghdr_type =
	target_lookup_sym(target,"struct msghdr",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);

    if (data->sockaddr_type)
	target_decoder_binding_add(tdb,data->sockaddr_type,
				   os_linux_sockaddr_snprintf);
    if (data->msghdr_type)
	target_decoder_binding_add(tdb,data->msghdr_type,
				   os_linux_msghdr_snprintf);

    return data;
}

int os_linux_generic_decoder_lib_unbind(struct target_decoder_binding *tdb,
					void *_data) {
    struct os_linux_generic_decoder_data *data =
	(struct os_linux_generic_decoder_data *)_data;

    if (data) {
	if (data->sockaddr_un_type)
	    bsymbol_release(data->sockaddr_un_type);
	if (data->sockaddr_in_type)
	    bsymbol_release(data->sockaddr_in_type);
	if (data->sockaddr_in6_type)
	    bsymbol_release(data->sockaddr_in6_type);
	if (data->sockaddr_type)
	    bsymbol_release(data->sockaddr_type);
	if (data->msghdr_type)
	    bsymbol_release(data->msghdr_type);
	free(data);
    }

    return 0;
}

struct target_decoder_lib os_linux_generic_decoder_lib = {
    .name = "os_linux_generic_decoder_lib",
    .bind = os_linux_generic_decoder_lib_bind,
    .unbind = os_linux_generic_decoder_lib_unbind,
};

void os_linux_generic_decoder_lib_register(void) {
    target_decoder_lib_register(&os_linux_generic_decoder_lib);
}
