/*
 * GSSAPI authentication.
 *
 * Copyright (C) 1998-2001 Andrew Tridgell <tridge@samba.org>
 * Copyright (C) 2001-2002 Martin Pool <mbp@samba.org>
 * Copyright (C) 2002-2008 Wayne Davison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

#include "rsync.h"

#ifdef GSSAPI_OPTION

#define RSYNC_GSS_SERVICE "rsync"

struct init_context_data {
    gss_cred_id_t          initiator_cred_handle;
    gss_ctx_id_t           *context_handle;
    gss_name_t             target_name;
    gss_OID                mech_type;
    OM_uint32              req_flags;
    OM_uint32              time_req;
    gss_channel_bindings_t input_chan_bindings;
    gss_OID                *actual_mech_type;
    OM_uint32              *ret_flags;
    OM_uint32              *time_rec;
};

struct accept_context_data {
    gss_ctx_id_t           *context_handle;
    gss_cred_id_t          acceptor_cred_handle;
    gss_channel_bindings_t input_chan_bindings;
    gss_name_t             *src_name;
    gss_OID                *mech_type;
    OM_uint32              *ret_flags;
    OM_uint32              *time_rec;
    gss_cred_id_t          *delegated_cred_handle;
};

int auth_gss_client(int fd, const char *host)
{
    gss_ctx_id_t ctxt = GSS_C_NO_CONTEXT;
    gss_name_t target_name = GSS_C_NO_NAME;
    struct init_context_data cb_data;
    char *buffer;
    int status;
    OM_uint32 maj_stat, min_stat;

    buffer = new_array(char, (strlen(host) + 2 + strlen(RSYNC_GSS_SERVICE)));
    if(!(buffer))
	    out_of_memory("auth_gss_client");

    sprintf(buffer, "%s@%s", RSYNC_GSS_SERVICE, host);
    
    import_gss_name(&target_name, buffer, GSS_C_NT_HOSTBASED_SERVICE);
    free(buffer);

    cb_data.initiator_cred_handle = GSS_C_NO_CREDENTIAL;
    cb_data.context_handle = &ctxt;
    cb_data.target_name = target_name;
    cb_data.mech_type = GSS_C_NO_OID;
    cb_data.req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
    cb_data.time_req = 0;
    cb_data.input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
    cb_data.actual_mech_type = NULL;
    cb_data.ret_flags = NULL;
    cb_data.time_rec = NULL;

    status = do_gss_dialog(fd, 0, &cb_init_sec_context, (void *)&cb_data);
    if(ctxt != GSS_C_NO_CONTEXT)
	maj_stat = gss_delete_sec_context(&min_stat, &ctxt, GSS_C_NO_BUFFER);
    free_gss_name(&target_name);

    return status;
}

/*
 * The call back function for a gss_init_sec_context dialog
 */
OM_uint32 cb_init_sec_context(OM_uint32 *min_statp, gss_buffer_t in_token, gss_buffer_t out_token, void *cb_data)
{
    struct init_context_data *context_data;
   
    context_data = (struct init_context_data *) cb_data;
    return gss_init_sec_context(min_statp ,
				    context_data->initiator_cred_handle, 
				    context_data->context_handle,
				    context_data->target_name, 
				    context_data->mech_type, 
				    context_data->req_flags, 
				    context_data->time_req, 
				    context_data->input_chan_bindings,
				    in_token,
				    context_data->actual_mech_type,
				    out_token, 
				    context_data->ret_flags,	
				    context_data->time_rec);
}

/* Possibly negotiate authentication with the client.  Use "leader" to
 * start off the auth if necessary.
 *
 * Return NULL if authentication failed.  Return "" if anonymous access.
 * Otherwise return username.
 */
char *auth_gss_server(int fd, int module, const char *host,
                      const char *addr, const char *leader)
{
    struct accept_context_data cb_data;
    gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    OM_uint32 ret_flags;
    char *users = lp_auth_users(module);
    OM_uint32 maj_stat, min_stat;
    gss_name_t server_name = GSS_C_NO_NAME;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_OID doid = GSS_C_NO_OID;
    char *user = NULL;

    /* if no auth list then authentication failed! */
    if (!users || !*users)
        return NULL;

    import_gss_name(&server_name, RSYNC_GSS_SERVICE, GSS_C_NT_HOSTBASED_SERVICE);

    maj_stat = gss_acquire_cred(&min_stat, server_name, GSS_C_INDEFINITE,
				GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
				&server_creds, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE) {
        error_gss(FLOG, maj_stat, min_stat, "error acquiring credentials on module %s from %s (%s)", lp_name(module), host, addr);
        return NULL;
    }
    
    /*maj_stat = gss_inquire_cred(&min_stat, server_creds, &temp_name, NULL, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE) {
	error_gss(FLOG, maj_stat, min_stat, "error acquiring credentials on module %s from %s (%s)", lp_name(module), host, addr);
	return NULL;
    }
    canonical_name =export_name(temp_name);
    free_gss_name(&temp_name);
    if(canonical_name == NULL) {
	printf("failed export name\n");
	return NULL;
	}*/

    io_printf(fd, "%s\n", leader);
    //free(canonical_name);

    cb_data.context_handle = &context;
    cb_data.acceptor_cred_handle = server_creds;
    cb_data.input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
    cb_data.src_name = &client_name;
    cb_data.mech_type = &doid;
    cb_data.ret_flags = &ret_flags;
    cb_data.time_rec = NULL;
    cb_data.delegated_cred_handle = NULL;

    if(do_gss_dialog(fd, -1, &cb_accept_sec_context, (void *)&cb_data) < 0)
	return NULL;

    user = get_cn(client_name, doid);

    free_gss_name(&server_name);
    free_gss_name(&client_name);
    
    return user;
}

/*
 * The call back function for a gss_accept_sec_context dialog
 */
OM_uint32 cb_accept_sec_context(OM_uint32 *min_statp, gss_buffer_t in_token, gss_buffer_t out_token, void *cb_data)
{
    struct accept_context_data *context_data;
    
    context_data = (struct accept_context_data *) cb_data;
    return gss_accept_sec_context(min_statp ,
				  context_data->context_handle,
				  context_data->acceptor_cred_handle, 
				  in_token,
				  context_data->input_chan_bindings,
				  context_data->src_name,
				  context_data->mech_type, 
				  out_token, 
				  context_data->ret_flags,
				  context_data->time_rec,	
				  context_data->delegated_cred_handle);
}

void free_gss_buffer(gss_buffer_t gss_buffer)
{
    OM_uint32 maj_stat, min_stat;
    
    if(gss_buffer->length > 0) {
	maj_stat = gss_release_buffer(&min_stat, gss_buffer);
	if (maj_stat != GSS_S_COMPLETE) {
	    error_gss(FWARNING, maj_stat, min_stat, "can't release a buffer");
	}
    }
}

void free_gss_name(gss_name_t *gss_buffer)
{
    OM_uint32 maj_stat, min_stat;
    
    if(*gss_buffer != GSS_C_NO_NAME) {
	maj_stat = gss_release_name(&min_stat, gss_buffer);
	if (maj_stat != GSS_S_COMPLETE) {
	    error_gss(FWARNING, maj_stat, min_stat, "can't release a name");
	}	
    }
}

void import_gss_name(gss_name_t *gss_name, const char *name, gss_OID type)
{
    gss_buffer_desc gssname;
    OM_uint32 maj_stat, min_stat;
    
    if (!(gssname.value = strdup(name)))
	out_of_memory("import_gss_name");
    gssname.length = strlen(name) +1 ;
    
    maj_stat = gss_import_name(&min_stat, &gssname,
			       type,
			       gss_name);

    if (maj_stat != GSS_S_COMPLETE) {
	    error_gss(FLOG, maj_stat, min_stat, "can't resolve %s", name);
    }
    free_gss_buffer(&gssname);
}

char *export_name(const gss_name_t input_name)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc exported_name;
    char *exported;
    gss_OID name_oid;

    exported = NULL;

    maj_stat = gss_display_name(&min_stat, input_name, &exported_name, &name_oid);
    if (maj_stat != GSS_S_COMPLETE) {
	error_gss(FLOG, maj_stat, min_stat, "can't get display name");
	return NULL;
    }

    if(exported_name.length > 0) {
	if (!(exported = strdup(exported_name.value)))
	    out_of_memory("export_name");
    }
    
    free_gss_buffer(&exported_name);

    return exported;
}

void error_gss(enum logcode code, OM_uint32 major, OM_uint32 minor, const char *format, ...)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc gss_msg = GSS_C_EMPTY_BUFFER;
    OM_uint32 msg_ctx;
    va_list ap;
    char message[BIGPATHBUFLEN];

    va_start(ap, format);
    vsnprintf(message, sizeof message, format, ap);
    va_end(ap);
    
    msg_ctx = 0;
    if(major != GSS_S_FAILURE) //Don't print unspecified failure, the message is useless
	do {
	    maj_stat = gss_display_status(&min_stat, major,
					  GSS_C_GSS_CODE, GSS_C_NULL_OID, &msg_ctx, &gss_msg);
	    rprintf(FERROR, "GSS-API error: %s: %s\n", message, (char *) gss_msg.value);
	    free_gss_buffer(&gss_msg);
	} while(msg_ctx != 0);
    
    if(minor != 0) {
	do {
	    maj_stat = gss_display_status(&min_stat, minor,
					  GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &gss_msg);
	    rprintf(FERROR, "GSS-API error: %s: %s\n",message, (char *) gss_msg.value);
	    free_gss_buffer(&gss_msg);
	} while(msg_ctx != 0);
    }
}

/*
 * This function manage a gss dialog
 * gss tokens are eaten by a call-back function and then send by this function.
 * Argument to this function can be passed throught the cb_data argument
 * When told to act as a server, it just begin to wait for a first token before beginning operation
 * on it
 */
int do_gss_dialog(int fd, 
		  int isServer,
		  OM_uint32 (*eat_token)(OM_uint32 *,gss_buffer_t , gss_buffer_t , void *),
		  void *cb_data)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    
    if(isServer)
	recv_gss_token(fd, &in_token);

    do {
	maj_stat = (*eat_token)(&min_stat, &in_token, &out_token, cb_data);
	free_gss_buffer(&in_token);	
	if (maj_stat != GSS_S_COMPLETE
	    && maj_stat != GSS_S_CONTINUE_NEEDED) {
	    error_gss(FLOG, maj_stat, min_stat, "error during dialog");
	    return -1;
	}
	
	if (out_token.length != 0) {
	    send_gss_token(fd, &out_token);
	}
	free_gss_buffer(&out_token);	
	
	if (maj_stat == GSS_S_CONTINUE_NEEDED) {
	    recv_gss_token(fd, &in_token);
	}
    } while (maj_stat == GSS_S_CONTINUE_NEEDED);
    
    return 0;
}

char *get_cn(const gss_name_t input_name, const gss_OID mech_type)
{
    OM_uint32 maj_stat, min_stat;
    gss_name_t output_name;
    gss_buffer_desc exported_name;
    char *cn;

    cn = NULL;
    maj_stat = gss_canonicalize_name(&min_stat, input_name, mech_type, &output_name);
    if(maj_stat != GSS_S_COMPLETE) {
	error_gss(FLOG, maj_stat, min_stat, "canonizing name");
	return NULL;
    }

    maj_stat = gss_export_name(&min_stat, output_name, &exported_name);
    if(maj_stat != GSS_S_COMPLETE) {
	error_gss(FLOG, maj_stat, min_stat, "canonizing name");
	return NULL;
    }
    if(exported_name.length > 0) {
	if (!(cn = strdup(exported_name.value)))
	    out_of_memory("auth_server");
    }

    free_gss_name(&output_name);
    free_gss_buffer(&exported_name);

    return cn;
}

void send_gss_token(int fd, gss_buffer_t token)
{
    write_int(fd, token->length);
    write_buf(fd, token->value, token->length);
    
}

void recv_gss_token(int fd, gss_buffer_t token)
{
    token->length = read_int(fd);
    if(token->length > 0) {
	if(!(token->value = new_array(char, token->length)))
	    out_of_memory("recv_gss_token");
	read_buf(fd, token->value, token->length);
    }
}
#endif //GSSAPI_OPTION
