#include <ruby.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <uv.h>
#include <arpa/inet.h>
#include "http_parser.h"

#define SERVER_SOFTWARE "Ricer"
#define MAX_HEADER_SIZE 4096

typedef enum last_callback {
    CB_URL,
    CB_HEADER_FIELD,
    CB_HEADER_VALUE,
    CB_BODY,
    CB_COMPLETE
} last_callback_t;

typedef struct client {
    uv_stream_t socket;
    http_parser_settings parser_settings;
    http_parser parser;
    last_callback_t last_callback;
    size_t total_header_size;
    char* url;
    size_t url_len;
    char* header_field;
    size_t header_field_len;
    char* header_value;
    size_t header_value_len;
    VALUE body;
    bool shutdown;
    bool sent_server_header;
    VALUE env;
} client_t;

static VALUE globals;

static VALUE Ricer;
static ID i_new;
static ID i_call;
static ID i_to_i;
static ID i_each;
static ID i_close;
static uint16_t port;
static VALUE app = Qnil;
static uv_loop_t* loop;

static VALUE StringIO;

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
static VALUE s_crlf;
static VALUE s_colon_space;

static VALUE sRackInput;
static VALUE sRackErrors;
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
    rb_gc_unregister_address(&client->body);
    rb_gc_unregister_address(&client->env);
    free(client);
}

static void on_shutdown(uv_shutdown_t* req, int status)
{
    free(req);
    uv_close((uv_handle_t*)req->handle, on_close);
}

static int on_http_url(http_parser* parser, const char* buff, size_t length)
{
    client_t* client = (client_t*)parser->data;
    if((client->total_header_size += length) > MAX_HEADER_SIZE) {
        // headers too long
        return 1;
    }
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
    cgi_header_name[client->header_field_len + 5] = 0;
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
    if((client->total_header_size += length) > MAX_HEADER_SIZE) {
        // headers too long
        return 1;
    }
    
    client->header_field = realloc(client->header_field, client->header_field_len + length);
    memcpy(client->header_field + client->header_field_len, buff, length);
    client->header_field_len += length;
    
    client->last_callback = CB_HEADER_FIELD;
    
    return 0;
}

static int on_http_body(http_parser* parser, const char* buff, size_t length)
{
    client_t* client = (client_t*)parser->data;
    if((client->total_header_size += length) > MAX_HEADER_SIZE) {
        // headers too long
        return 1;
    }
    rb_str_cat(client->body, buff, length);
    client->last_callback = CB_BODY;
    return 0;
}

static int on_http_header_value(http_parser* parser, const char* buff, size_t length)
{
    client_t* client = (client_t*)parser->data;
    if((client->total_header_size += length) > MAX_HEADER_SIZE) {
        // headers too long
        return 1;
    }
    
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

static VALUE collect_headers(VALUE i, VALUE str, int argc, VALUE* argv)
{
    if(argc < 1 || TYPE(argv[0]) != T_ARRAY) {
        return Qnil;
    }
    VALUE* nv = RARRAY_PTR(argv[0]);
    if(RARRAY_LEN(argv[0]) < 2) {
        return Qnil;
    }
    
    char* value = rb_string_value_cstr(&nv[1]);
    
    while(value) {
        rb_str_concat(str, nv[0]);
        rb_str_concat(str, s_colon_space);
        char* next = strchr(value, '\n');
        if(next) {
            rb_str_cat(str, value, (int)(next - value));
            value = next + 1;
        } else {
            rb_str_cat(str, value, strlen(value));
            value = NULL;
        }
        rb_str_concat(str, s_crlf);
    }
    return Qnil;
}

static VALUE collect_body(VALUE i, VALUE str, int argc, VALUE* argv)
{
    if(argc < 1) {
        return Qnil;
    }
    rb_str_concat(str, argv[0]);
    return Qnil;
}

static void on_write(uv_write_t* req, int status)
{
    client_t* client = req->handle->data;
    free(((uv_buf_t*)req->data)->base);
    free(req->data);
    free(req);
}

static int on_http_message_complete(http_parser* parser)
{
    client_t* client = (client_t*)parser->data;
    
    // set url, path name, etc:
    rb_hash_aset(client->env, sSCRIPT_NAME, s_empty);
    rb_hash_aset(client->env, sREQUEST_URI, rb_obj_freeze(rb_str_new(client->url, client->url_len)));
    char* query_string = memchr(client->url, '?', client->url_len);
    if(query_string) {
        VALUE path = rb_obj_freeze(rb_str_new(client->url, (size_t)(query_string - client->url)));
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
    
    // set IO streams:
    rb_hash_aset(client->env, sRackInput, rb_funcall(StringIO, i_new, 1, client->body));
    rb_hash_aset(client->env, sRackErrors, rb_stderr);
    
    // call into app
    VALUE response = rb_funcall(app, i_call, 1, client->env);
    if(TYPE(response) != T_ARRAY || RARRAY_LEN(response) < 3) {
        // bad response, bail out
        printf("response was not array or len < 3\n");
        return 1;
    }
    
    VALUE* response_ary = RARRAY_PTR(response);
    VALUE v_status = response_ary[0];
    VALUE v_headers = response_ary[1];
    VALUE v_body = response_ary[2];
    
    int status = 0;
    if(TYPE(v_status) != T_FIXNUM) {
        v_status = rb_funcall(v_status, i_to_i, 0);
        if(TYPE(v_status) != T_FIXNUM) {
            printf("could not convert status to fixnum\n");
            return 1;
        }
    }
    status = FIX2INT(v_status);
    
    char buff[64];
    sprintf(buff, "HTTP/1.1 %d OK\r\n", status);
    VALUE v_response_str = rb_str_new(buff, strlen(buff));
    rb_block_call(v_headers, i_each, 0, NULL, collect_headers, v_response_str);
    rb_str_concat(v_response_str, s_crlf);
    rb_block_call(v_body, i_each, 0, NULL, collect_body, v_response_str);
    if(rb_respond_to(v_body, i_close)) {
        rb_funcall(v_body, i_close, 0);
    }
    
    uv_buf_t* b = malloc(sizeof(uv_buf_t));
    b->len = RSTRING_LEN(v_response_str);
    b->base = malloc(b->len);
    memcpy(b->base, RSTRING_PTR(v_response_str), b->len);
    uv_write_t* req = malloc(sizeof(uv_write_t));
    req->data = b;
    uv_write(req, &client->socket, b, 1, on_write);
    
    client->last_callback = CB_COMPLETE;
    
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
    client->body = rb_str_new("", 0);
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

static void http_bad_request(client_t* client)
{
    uv_buf_t* b = malloc(sizeof(uv_buf_t));
    const char* response = "HTTP/1.1 400 Bad Request\r\nServer: " SERVER_SOFTWARE "\r\n\r\n<h1>Bad Request</h1>";
    b->len = strlen(response);
    b->base = malloc(b->len);
    memcpy(b->base, response, b->len);
    uv_write_t* req = malloc(sizeof(uv_write_t));
    req->data = b;
    uv_write(req, &client->socket, b, 1, on_write);
    client->shutdown = true;
    uv_shutdown_t* shutdown = malloc(sizeof(uv_shutdown_t));
    uv_shutdown(shutdown, &client->socket, on_shutdown);
}

static void on_read(uv_stream_t* stream, ssize_t nread, uv_buf_t buff)
{
    client_t* client = (client_t*)stream->data;
    if(nread < 0) {
        /*
        client->shutdown = 1;
        uv_shutdown_t* shutdown = malloc(sizeof(uv_shutdown_t));
        uv_shutdown(shutdown, &client->socket, on_shutdown);
        */
    } else if(nread == 0) {
        if(http_parser_execute(&client->parser, &client->parser_settings, buff.base, nread) != (size_t)nread) {
            http_bad_request(client);
        }
    } else {
        if(http_parser_execute(&client->parser, &client->parser_settings, buff.base, nread) != (size_t)nread) {
            http_bad_request(client);
        } else {
            if(client->last_callback == CB_COMPLETE) {
                client->shutdown = 1;
                uv_shutdown_t* shutdown = malloc(sizeof(uv_shutdown_t));
                uv_shutdown(shutdown, &client->socket, on_shutdown);
            } else {
                uv_read_start((uv_stream_t*)&client->socket, uv_ricer_alloc, on_read);
            }
        }
    }
    uv_ricer_free(buff);
}

static void on_connection(uv_stream_t* server, int status)
{
    client_t* client = malloc(sizeof(client_t));
    memset(client, 0, sizeof(client_t));
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
    client->parser_settings.on_body = on_http_body;
    client->parser_settings.on_message_complete = on_http_message_complete;
    
    client->env = Qnil;
    rb_gc_register_address(&client->env);
    client->body = Qnil;
    rb_gc_register_address(&client->body);
    
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
    run(addr, app);
    return Qnil;
}

static void on_sigint(int signal)
{
    rb_interrupt();
}

void Init_ricer()
{    
    rb_gc_register_address(&app);
    
    globals = rb_ary_new();
    rb_gc_register_address(&globals);
    
    i_new = rb_intern("new");
    i_call = rb_intern("call");
    i_to_i = rb_intern("to_i");
    i_each = rb_intern("each");
    i_close = rb_intern("close");
    
    Ricer = rb_define_module("Ricer");
    rb_ary_push(globals, Ricer);
    rb_const_set(Ricer, rb_intern("VERSION"), rb_str_new_cstr("0.1.0"));
    rb_define_singleton_method(Ricer, "run", Ricer_run, 3);
    
    #define GLOBAL_STR(var, str) var = rb_obj_freeze(rb_str_new_cstr(str)); rb_ary_push(globals, var);
    
    GLOBAL_STR(s_empty,             "");
    GLOBAL_STR(s_crlf,              "\r\n");
    GLOBAL_STR(s_colon_space,       ": ");
    GLOBAL_STR(sREQUEST_METHOD,     "REQUEST_METHOD");
    GLOBAL_STR(sREQUEST_PATH,       "REQUEST_PATH");
    GLOBAL_STR(sREQUEST_URI,        "REQUEST_URI");
    GLOBAL_STR(sSCRIPT_NAME,        "SCRIPT_NAME");
    GLOBAL_STR(sPATH_INFO,          "PATH_INFO");
    GLOBAL_STR(sQUERY_STRING,       "QUERY_STRING");
    GLOBAL_STR(sSERVER_NAME,        "SERVER_NAME");
    GLOBAL_STR(sSERVER_SOFTWARE,    "SERVER_SOFTWARE");
    GLOBAL_STR(sSERVER_PORT,        "SERVER_PORT");
    GLOBAL_STR(sRicer,              SERVER_SOFTWARE);
    
    GLOBAL_STR(sRackInput,          "rack.input");
    GLOBAL_STR(sRackErrors,         "rack.errors");
    GLOBAL_STR(sRackVersion,        "rack.version");
    GLOBAL_STR(sRackMultithread,    "rack.multithread");
    GLOBAL_STR(sRackMultiprocess,   "rack.multiprocess");
    GLOBAL_STR(sRackRunOnce,        "rack.run_once");
    GLOBAL_STR(sRackUrlScheme,      "rack.url_scheme");
    GLOBAL_STR(HTTP_URL_SCHEME,     "http");
    
    RACK_VERSION = rb_obj_freeze(rb_ary_new3(2, INT2FIX(1), INT2FIX(1)));
    rb_ary_push(globals, RACK_VERSION);
    
    rb_require("stringio");
    StringIO = rb_const_get(rb_cObject, rb_intern("StringIO"));
    rb_ary_push(globals, StringIO);
    
    signal(SIGINT, on_sigint);
    
    #undef GLOBAL_STR
}