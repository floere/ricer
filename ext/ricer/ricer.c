#include <ruby.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <uv.h>
#include <arpa/inet.h>
#include "http_parser.h"

typedef enum last_callback {
    CB_URL,
    CB_HEADER_FIELD,
    CB_HEADER_VALUE
} last_callback_t;

typedef struct client {
    uv_stream_t socket;
    http_parser_settings parser_settings;
    http_parser parser;
    last_callback_t last_callback;
    char* url;
    size_t url_len;
    char* header_field;
    size_t header_field_len;
    char* header_value;
    size_t header_value_len;
    VALUE env;
} client_t;

static VALUE globals;

static VALUE Ricer;
static ID i_call;
static uint16_t port;
static VALUE app = Qnil;
static uv_loop_t* loop;

static VALUE sREQUEST_METHOD;
static VALUE sREQUEST_PATH;
static VALUE sREQUEST_URI;
static VALUE sSCRIPT_NAME;
static VALUE sPATH_INFO;
static VALUE sQUERY_STRING;
static VALUE sSERVER_NAME;
static VALUE sSERVER_SOFTWARE;
static VALUE sSERVER_PORT;
static VALUE sREQUEST_PATH;
static VALUE sRicer;
static VALUE s_empty;

static VALUE sRackVersion;
static VALUE RACK_VERSION;
static VALUE sRackMultithread;
static VALUE sRackMultiprocess;
static VALUE sRackRunOnce;
static VALUE sRackUrlScheme;
static VALUE HTTP_URL_SCHEME;

static uv_buf_t uv_ricer_alloc(uv_handle_t* handle, size_t suggested_size)
{
    return uv_buf_init((char*)malloc(suggested_size), (uint32_t)suggested_size);
}

static void uv_ricer_free(uv_buf_t buff)
{
    free(buff.base);
}

static int on_http_url(http_parser* parser, const char* buff, size_t length)
{
    client_t* client = (client_t*)parser->data;
    client->url = realloc(client->url, client->url_len + length);
    memcpy(client->url + client->url_len, buff, length);
    client->url_len += length;
    client->last_callback = CB_URL;
    return 0;
}

static void save_last_header_value(client_t* client)
{
    char cgi_header_name[5 /* HTTP_ */ + client->header_field_len + 1];
    memcpy(cgi_header_name, "HTTP_", 5);
    for(size_t i = 0; i < client->header_field_len; i++) {
        if(client->header_field[i] == '-') {
            cgi_header_name[i + 5] = '_';
        } else {
            cgi_header_name[i + 5] = toupper(client->header_field[i]);
        }
    }
    VALUE header_name = rb_obj_freeze(rb_str_new(cgi_header_name, 5 + client->header_field_len));
    VALUE header_value = rb_obj_freeze(rb_str_new(client->header_value, client->header_value_len));
    rb_hash_aset(client->env, header_name, header_value);
    free(client->header_field);
    client->header_field = NULL;
    client->header_field_len = 0;
    free(client->header_value);
    client->header_value = NULL;
    client->header_value_len = 0;
}

static int on_http_header_field(http_parser* parser, const char* buff, size_t length)
{
    client_t* client = (client_t*)parser->data;
    if(client->last_callback == CB_HEADER_VALUE) {
        // we need to save the last header/value pair
        save_last_header_value(client);
    }
    
    client->header_field = realloc(client->header_field, client->header_field_len + length);
    memcpy(client->header_field + client->header_field_len, buff, length);
    client->header_field_len += length;
    
    client->last_callback = CB_HEADER_FIELD;
    
    return 0;
}

static int on_http_header_value(http_parser* parser, const char* buff, size_t length)
{
    client_t* client = (client_t*)parser->data;
    
    client->header_value = realloc(client->header_value, client->header_value_len + length);
    memcpy(client->header_value + client->header_value_len, buff, length);
    client->header_value_len += length;
    
    client->last_callback = CB_HEADER_VALUE;
    
    return 0;
}

static int on_http_headers_complete(http_parser* parser)
{
    client_t* client = (client_t*)parser->data;
    if(client->last_callback == CB_HEADER_VALUE) {
        // we need to save the last header/value pair
        save_last_header_value(client);
    }
    return 0;
}

static int on_http_message_complete(http_parser* parser)
{
    client_t* client = (client_t*)parser->data;
    
    // set url, path name, etc:
    rb_hash_aset(client->env, sSCRIPT_NAME, s_empty);
    rb_hash_aset(client->env, sREQUEST_URI, rb_obj_freeze(rb_str_new(client->url, client->url_len)));
    char* query_string = memchr(client->url, '?', client->url_len);
    if(query_string) {
        VALUE path = rb_obj_freeze(rb_str_new(client->url, (size_t)(query_string - client->url_len)));
        rb_hash_aset(client->env, sPATH_INFO, path);
        rb_hash_aset(client->env, sREQUEST_PATH, path);
        rb_hash_aset(client->env, sQUERY_STRING, rb_obj_freeze(rb_str_new(query_string + 1, client->url_len - (size_t)(query_string - client->url) - 1)));
    } else {
        VALUE path = rb_obj_freeze(rb_str_new(client->url, client->url_len));
        rb_hash_aset(client->env, sPATH_INFO, path);
        rb_hash_aset(client->env, sREQUEST_PATH, path);
        rb_hash_aset(client->env, sQUERY_STRING, s_empty);
    }
    
    // set request method:
    rb_hash_aset(client->env, sREQUEST_METHOD, rb_obj_freeze(rb_str_new_cstr(http_method_str(parser->method))));
    
    // call into app
    rb_funcall(app, i_call, 1, client->env);
    
    // done
    return 0;
}

static int on_http_message_begin(http_parser* parser)
{
    client_t* client = (client_t*)parser->data;
    
    if(client->url) {
        free(client->url);
        client->url = NULL;
        client->url_len = 0;
    }
    
    // initialize environment for new request:
    client->env = rb_hash_new();
    rb_hash_aset(client->env, sSERVER_SOFTWARE, sRicer);
    rb_hash_aset(client->env, sSERVER_PORT, INT2FIX(port));
    rb_hash_aset(client->env, sRackVersion, RACK_VERSION);
    rb_hash_aset(client->env, sRackMultithread, Qfalse);
    rb_hash_aset(client->env, sRackMultiprocess, Qfalse /* or Qtrue? i have no clue ... */);
    rb_hash_aset(client->env, sRackRunOnce, Qfalse);
    rb_hash_aset(client->env, sRackUrlScheme, HTTP_URL_SCHEME /* TODO return https if applicable */);
    
    return 0;
}

static void on_close(uv_handle_t* stream)
{
    client_t* client = (client_t*)stream->data;
    if(client->url) {
        free(client->url);
    }
    if(client->header_field) {
        free(client->header_field);
    }
    if(client->header_value) {
        free(client->header_value);
    }
    rb_gc_unregister_address(&client->env);
    free(client);
}

static void on_read(uv_stream_t* stream, ssize_t nread, uv_buf_t buff)
{
    client_t* client = (client_t*)stream->data;
    if(nread < 0) {
        uv_close((uv_handle_t*)&client->socket, on_close);
    } else if(nread == 0) {
        // vvvvvv
        http_parser_execute(&client->parser, &client->parser_settings, buff.base, nread);
        // ^^^^^^ TODO check for error
    } else {
        // vvvvvv
        http_parser_execute(&client->parser, &client->parser_settings, buff.base, nread);
        // ^^^^^^ TODO check for error
        uv_read_start((uv_stream_t*)&client->socket, uv_ricer_alloc, on_read);
    }
    uv_ricer_free(buff);
}

static void on_connection(uv_stream_t* server, int status)
{
    client_t* client = calloc(1, sizeof(client_t));
    uv_tcp_init(loop, (uv_tcp_t*)&client->socket);
    uv_accept(server, &client->socket);
    
    http_parser_init(&client->parser, HTTP_REQUEST);
    client->parser.data = client;
    client->socket.data = client;
    client->parser_settings.on_message_begin = on_http_message_begin;
    client->parser_settings.on_url = on_http_url;
    client->parser_settings.on_header_field = on_http_header_field;
    client->parser_settings.on_header_value = on_http_header_value;
    client->parser_settings.on_headers_complete = on_http_headers_complete;
    client->parser_settings.on_message_complete = on_http_message_complete;
    
    client->env = Qnil;
    rb_gc_register_address(&client->env);
    
    uv_read_start((uv_stream_t*)&client->socket, uv_ricer_alloc, on_read);
}

static void run(struct sockaddr_in addr, VALUE _app)
{
    const char* err = NULL;
    const char* msg = NULL;
    int errcode = 0;
    
    app = _app;
    loop = uv_loop_new();
    
    uv_tcp_t tcp;
    uv_tcp_init(loop, &tcp);
    if((errcode = uv_tcp_bind(&tcp, addr)) != 0) {
        err = "uv_tcp_bind failed";
        msg = uv_strerror(uv_last_error(loop));
        goto cleanup;
    }
    if((errcode = uv_listen((uv_stream_t*)&tcp, 16, on_connection)) != 0) {
        err = "uv_tcp_listen failed";
        msg = uv_strerror(uv_last_error(loop));
        goto cleanup;
    }
    
    uv_run(loop);
    
cleanup:
    uv_loop_delete(loop);
    app = Qnil;
    loop = NULL;
    if(err) {
        rb_raise(rb_eRuntimeError, "%s: %s (%d)", err, msg, errcode);
    }
}

static VALUE Ricer_run(VALUE self, VALUE v_address, VALUE v_port, VALUE app)
{
    if(loop) {
        rb_raise(rb_eRuntimeError, "Ricer instance already running");
    }
    long _port = FIX2INT(v_port);
    if(_port <= 0 || _port >= 65536) {
        // out of range
        rb_raise(rb_eArgError, "port number outside valid range");
    }
    char* addr_str = rb_string_value_cstr(&v_address);
    port = (uint16_t)_port;
    struct sockaddr_in addr = uv_ip4_addr(addr_str, port);
    /*
    if(inet_aton(addr_str, &addr.sin_addr) == 0) {
        // invalid address
        rb_raise(rb_eArgError, "invalid address: %s", strerror(errno));
    }
    addr.sin_port = htons((uint16_t)_port);
    addr.sin_family = AF_INET;*/
    run(addr, app);
    return Qnil;
}

void Init_ricer()
{    
    rb_gc_register_address(&app);
    
    globals = rb_ary_new();
    rb_gc_register_address(&globals);
    
    i_call = rb_intern("call");
    
    Ricer = rb_define_module("Ricer");
    rb_ary_push(globals, Ricer);
    rb_define_singleton_method(Ricer, "run", Ricer_run, 3);
    
    #define GLOBAL_STR(var, str) var = rb_obj_freeze(rb_str_new_cstr(str)); rb_ary_push(globals, var);
    
    GLOBAL_STR(s_empty,             "");
    GLOBAL_STR(sREQUEST_METHOD,     "REQUEST_METHOD");
    GLOBAL_STR(sREQUEST_PATH,       "REQUEST_PATH");
    GLOBAL_STR(sREQUEST_URI,        "REQUEST_URI");
    GLOBAL_STR(sSCRIPT_NAME,        "SCRIPT_NAME");
    GLOBAL_STR(sPATH_INFO,          "PATH_INFO");
    GLOBAL_STR(sQUERY_STRING,       "QUERY_STRING");
    GLOBAL_STR(sSERVER_NAME,        "SERVER_NAME");
    GLOBAL_STR(sSERVER_SOFTWARE,    "SERVER_SOFTWARE");
    GLOBAL_STR(sSERVER_PORT,        "SERVER_PORT");
    GLOBAL_STR(sRicer,              "Ricer");
    
    GLOBAL_STR(sRackVersion,        "rack.version");
    GLOBAL_STR(sRackMultithread,    "rack.multithread");
    GLOBAL_STR(sRackMultiprocess,   "rack.multiprocess");
    GLOBAL_STR(sRackRunOnce,        "rack.run_once");
    GLOBAL_STR(sRackUrlScheme,      "rack.url_scheme");
    GLOBAL_STR(HTTP_URL_SCHEME,     "http");
    
    RACK_VERSION = rb_obj_freeze(rb_ary_new3(2, INT2FIX(1), INT2FIX(1)));
    rb_ary_push(globals, RACK_VERSION);
    
    #undef GLOBAL_STR
}