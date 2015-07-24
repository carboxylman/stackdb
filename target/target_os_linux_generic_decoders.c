
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
    struct symbol *sockaddr_ptr_type;
    struct bsymbol *sockaddr_un_type;
    struct bsymbol *sockaddr_in_type;
    struct bsymbol *sockaddr_in6_type;
    struct bsymbol *msghdr_type;
    struct bsymbol *cmsghdr_type;
    struct bsymbol *cmsgcred_type;
};

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
	clone = value_reload_as_type(value,bsymbol_get_symbol(data->sockaddr_un_type),0);
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
	    nrc += Lsnprintf("{ .sun_family = AF_UNIX, .sun_path = \"@%s\" }",
			     &(v->buf[1]));
	else
	    nrc += Lsnprintf("{ .sun_family = AF_UNIX, .sun_path = \"%s\" }",
			     v->buf);
	value_free(v);
	value_free(clone);
	return nrc;
    }
    else if (family == AF_INET) {
	clone = value_reload_as_type(value,bsymbol_get_symbol(data->sockaddr_in_type),0);
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
	nrc += Lsnprintf("{ .sin_family = AF_INET, .sin_port = %hu, .sin_addr = { .s_addr = \"%s\" } }",
			 port,addrstr);
	value_free(clone);
	return nrc;
    }
    else if (family == AF_INET6) {
	clone = value_reload_as_type(value,bsymbol_get_symbol(data->sockaddr_in6_type),0);
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
	nrc += Lsnprintf("{ .sin6_family = AF_INET6, .sin6_port = %hu, .sin6_flowinfo = %u, .sin6_addr = { .s6_addr = \"%s\" }, .sin6_scope_id = %u }",
			 port,flowinfo,addrstr,scopeid);
	value_free(clone);
	return nrc;
    }
    else {
	return -1;
    }
}

int os_linux_iovec_snprintf(struct target *target,void *_data,
			    struct value *value,char *buf,int buflen) {
    struct os_linux_generic_decoder_data *data =
	(struct os_linux_generic_decoder_data *)_data;
    struct value *v;
    int nrc = 0;
    unum_t iovlen;
    int iovlen_noload = 0;
    int iovbase_noload = 0;
    ADDR iovbase;
    unsigned char *ibuf,*ibuf2;
    unsigned int j;
    int unprintable;

    if (!data) {
	errno = EINVAL;
	return -1;
    }

#define Lsnprintf(...)							\
    snprintf((buf != NULL) ? buf + nrc : NULL,(buflen != 0) ? buflen - nrc : 0,	\
	     ## __VA_ARGS__)

    v = target_load_value_member(target,NULL,value,"iov_len",NULL,0);
    if (!v) {
	iovlen_noload = 1;
	iovlen = 0;
    }
    else {
	iovlen = v_unum(v);
	value_free(v);
    }

    v = target_load_value_member(target,NULL,value,"iov_base",NULL,0);
    if (!v)
	iovbase_noload = 1;
    else {
	iovbase = v_addr(v);
	value_free(v);
    }

    if (!iovbase_noload && iovbase != 0 && iovlen) {
	ibuf = malloc(iovlen + 1);
	if (!target_read_addr(target,iovbase,iovlen,ibuf)) {
	    nrc += Lsnprintf("{ .iov_base = 0x%"PRIxADDR,iovbase);
	}
	else {
	    ibuf[iovlen] = '\0';

	    /* Check for unprintable chars */
	    unprintable = 0;
	    for (j = 0; j < iovlen; ++j) {
		if (!isgraph(ibuf[j]) && !isspace(ibuf[j])) {
		    unprintable = 1;
		    break;
		}
	    }

	    if (unprintable) {
		//nrc += Lsnprintf("{ .iov_base = 0h");
		ibuf2 = malloc(iovlen * 2 + 1);
		for (j = 0; j < iovlen; ++j) {
		    //nrc += Lsnprintf("%hhx",ibuf[j]);
		    sprintf((char *)(ibuf2 + j * 2),"%.2hhx",ibuf[j]);
		}
		ibuf2[iovlen * 2] = '\0';

		nrc += Lsnprintf("{ .iov_base = 0h%s",ibuf2);
		free(ibuf2);
	    }
	    else
		nrc += Lsnprintf("{ .iov_base = \"%s\"",ibuf);
	}
	free(ibuf);
    }
    else if (!iovbase_noload) {
	nrc += Lsnprintf("{ .iov_base = 0x%"PRIxADDR,iovbase);
    }
    else
	nrc += Lsnprintf("{ .iov_base = ?");

    if (!iovlen_noload)
	nrc += Lsnprintf(", .iov_len = %"PRIuNUM" }",iovlen);
    else
	nrc += Lsnprintf(", .iov_len = ? }");

    return nrc;
}

int os_linux_msghdr_snprintf(struct target *target,void *_data,
			     struct value *value,char *buf,int buflen) {
    struct os_linux_generic_decoder_data *data =
	(struct os_linux_generic_decoder_data *)_data;
    struct value *clone;
    struct value *v,*v2;
    uint32_t namelen;
    int nrc = 0;
    int _trc;
    unum_t controllen;
    num_t iovlen;
    short iovlen_noload = 0,controllen_noload = 0;
    ADDR iov;
    struct symbol *type;
    int typesize;
    unsigned int i;
    ADDR control;
    unum_t cmsglen;
    int32_t cmsglevel,cmsgtype;
    unsigned char *ibuf,*ibuf2;
    unsigned int j;

    if (!data) {
	errno = EINVAL;
	return -1;
    }

#define Lsnprintf(...)							\
    snprintf((buf != NULL) ? buf + nrc : NULL,(buflen != 0) ? buflen - nrc : 0,	\
	     ## __VA_ARGS__)

    v = target_load_value_member(target,NULL,value,"msg_namelen",NULL,0);
    if (!v)
	return -1;
    namelen = v_u32(v);
    value_free(v);

    v = target_load_value_member(target,NULL,value,"msg_name",NULL,0);
    if (!v)
	return -1;
    /*
    clone = value_reload_as_type(v,data->sockaddr_ptr_type,LOAD_FLAG_AUTO_DEREF);
    */
    if (v_addr(v) != 0) {
	clone = target_load_type(target,bsymbol_get_symbol(data->sockaddr_type),
				 v_addr(v),0);
	if (!clone) {
	    value_free(v);
	    nrc += Lsnprintf("{ .msg_name = ?");
	}
	else {
	    nrc += Lsnprintf("{ .msg_name = ");
	    _trc = os_linux_sockaddr_snprintf(target,_data,clone,
					      buf+nrc,buflen-nrc);
	    if (_trc < 0)
		return -1;
	    else
		nrc += _trc;
	    value_free(clone);
	}
    }
    else {
	nrc += Lsnprintf(", .msg_name = 0x0");
    }
    nrc += Lsnprintf(", .msg_namelen = %u",namelen);
    value_free(v);

    v = target_load_value_member(target,NULL,value,"msg_iovlen",NULL,0);
    if (!v) {
	iovlen_noload = 1;
	iovlen = 0;
    }
    else {
	iovlen = v_num(v);
	value_free(v);
    }

    v = target_load_value_member(target,NULL,value,"msg_controllen",NULL,0);
    if (!v) {
	controllen_noload = 1;
	controllen = 0;
    }
    else {
	controllen = v_unum(v);
	value_free(v);
    }

    /*
     * iovecs.
     */
    if (iovlen > 0) {
	v = target_load_value_member(target,NULL,value,"msg_iov",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    nrc += Lsnprintf(", .msg_iov = ?");
	}
	else {
	    type = symbol_type_skip_ptrs(v->type);
	    typesize = symbol_type_full_bytesize(type);
	    nrc += Lsnprintf(", .msg_iov = [ ");
	    for (i = 0; i < iovlen; ++i) {
		if (i > 0) {
		    nrc += Lsnprintf(", ");
		}
		nrc += os_linux_iovec_snprintf(target,data,v,
					       (buf != NULL) ? buf + nrc : NULL,
					       (buflen != 0) ? buflen - nrc : 0);
		if ((i + 1) >= iovlen)
		    break;

		iov = value_addr(v) + typesize;
		value_free(v);
		v = target_load_type(target,type,iov,0);
		if (!v) {
		    nrc += Lsnprintf(" ? ");
		    break;
		}
	    }
	    nrc += Lsnprintf(" ]");
	}
    }
    else {
	v = target_load_value_member(target,NULL,value,"msg_iov",NULL,0);
	if (!v)
	    iov = 0x0;
	else {
	    iov = v_addr(v);
	    value_free(v);
	}
	nrc += Lsnprintf(", .msg_iov = %"PRIxADDR,iov);
    }

    if (iovlen_noload)
	nrc += Lsnprintf(", .msg_iovlen = ?");
    else
	nrc += Lsnprintf(", .msg_iovlen = %"PRIiNUM,iovlen);

    /*
     * Control data.
     */
    if (controllen > 0) {
	v = target_load_value_member(target,NULL,value,"msg_control",NULL,0);
	if (!v) {
	    nrc += Lsnprintf(", .msg_control = ?");
	}
	else {
	    control = v_addr(v);
	    value_free(v);

	    type = bsymbol_get_symbol(data->cmsghdr_type);
	    typesize = symbol_type_full_bytesize(type);
	    nrc += Lsnprintf(", .msg_control = [ ");
	    i = 0;
	    while ((i + typesize) <= controllen) {
		if (i > 0) {
		    nrc += Lsnprintf(", ");
		}

		v = target_load_type(target,type,control + i,0);
		if (!v) {
		    nrc += Lsnprintf(" ? ");
		    break;
		}

		v2 = target_load_value_member(target,NULL,v,"cmsg_len",NULL,0);
		if (!v2) {
		    nrc += Lsnprintf(" ? ");
		    value_free(v);
		    break;
		}
		cmsglen = v_unum(v2);
		if ((cmsglen + i) > controllen) {
		    nrc += Lsnprintf(" ? ");
		    value_free(v2);
		    value_free(v);
		    break;
		}
		else
		    value_free(v2);

		v2 = target_load_value_member(target,NULL,v,"cmsg_level",NULL,0);
		if (!v2) {
		    nrc += Lsnprintf(" ? ");
		    value_free(v);
		    break;
		}
		cmsglevel = v_i32(v2);
		value_free(v2);

		v2 = target_load_value_member(target,NULL,v,"cmsg_type",NULL,0);
		if (!v2) {
		    nrc += Lsnprintf(" ? ");
		    value_free(v);
		    break;
		}
		cmsgtype = v_i32(v2);
		value_free(v2);

		value_free(v);

		if (cmsglen > 0) {
		    /* Now read the data buf */
		    ibuf = malloc(cmsglen - typesize + 1);
		    if (!target_read_addr(target,control + i + typesize,
					  cmsglen - typesize,ibuf)) {
			nrc += Lsnprintf("{ .cmsg_len = %"PRIuNUM", .cmsg_level = %d, .cmsg_type = %d, .cmsg_data = ? }",
					 cmsglen,cmsglevel,cmsgtype);
		    }
		    else {
			/* Assume it's unprintable */
			ibuf2 = malloc((cmsglen - typesize) * 2 + 1);
			for (j = 0; j < (cmsglen - typesize); ++j) {
			    sprintf((char *)(ibuf2 + j * 2),"%.2hhx",ibuf[j]);
			}
			ibuf2[(cmsglen - typesize) * 2] = '\0';

			nrc += Lsnprintf("{ .cmsg_len = %"PRIuNUM", .cmsg_level = %d, .cmsg_type = %d, .cmsg_data = 0h%s }",
					 cmsglen,cmsglevel,cmsgtype,ibuf2);

			free(ibuf2);
		    }
		    free(ibuf);
		}
		else {
		    /* With a 0-length cmsglen, we can't continue. */
		    nrc += Lsnprintf("{ .cmsg_len = %"PRIuNUM", .cmsg_level = %d, .cmsg_type = %d, .cmsg_data = ? }",
					 cmsglen,cmsglevel,cmsgtype);
		    break;
		}

		i += cmsglen;
	    }
	    nrc += Lsnprintf(" ]");
	}
    }
    else {
	v = target_load_value_member(target,NULL,value,"msg_control",NULL,0);
	if (!v)
	    control = 0x0;
	else {
	    control = v_addr(v);
	    value_free(v);
	}
	nrc += Lsnprintf(", .msg_control = %"PRIxADDR,control);
    }

    if (controllen_noload)
	nrc += Lsnprintf(", .msg_controllen = ?");
    else
	nrc += Lsnprintf(", .msg_controllen = %"PRIiNUM,controllen);

    v = target_load_value_member(target,NULL,value,"msg_flags",NULL,0);
    if (!v)
	nrc += Lsnprintf(", .msg_flags = ?");
    else {
	nrc += Lsnprintf(", .msg_flags = %d",v_i32(v));
	value_free(v);
    }

    nrc += Lsnprintf(" }");

    return nrc;
}

void *os_linux_generic_decoder_lib_bind(struct target_decoder_binding *tdb) {
    struct os_linux_generic_decoder_data *data;
    struct target *target = tdb->target;
    struct bsymbol *bs;

    data = (struct os_linux_generic_decoder_data *)calloc(1,sizeof(*data));

    data->sockaddr_type =
	target_lookup_sym(target,"struct sockaddr",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    if (data->sockaddr_type)
	data->sockaddr_ptr_type =
	    target_create_synthetic_type_pointer(target,bsymbol_get_symbol(data->sockaddr_type));
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
    data->cmsghdr_type =
	target_lookup_sym(target,"struct cmsghdr",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    data->cmsgcred_type =
	target_lookup_sym(target,"struct cmsgcred",
			  NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);

    bs = target_lookup_sym(target,"struct iovec",
			   NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    if (bs) {
	target_decoder_binding_add(tdb,bs,os_linux_iovec_snprintf);
	bsymbol_release(bs);
	bs = NULL;
    }

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
	if (data->cmsgcred_type)
	    bsymbol_release(data->cmsgcred_type);
	if (data->cmsghdr_type)
	    bsymbol_release(data->cmsghdr_type);
	if (data->sockaddr_un_type)
	    bsymbol_release(data->sockaddr_un_type);
	if (data->sockaddr_in_type)
	    bsymbol_release(data->sockaddr_in_type);
	if (data->sockaddr_in6_type)
	    bsymbol_release(data->sockaddr_in6_type);
	if (data->sockaddr_ptr_type)
	    symbol_release(data->sockaddr_ptr_type);
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
