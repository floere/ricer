#include <ruby.h>
#include <stdlib.h>
#include <stdio.h>

static VALUE Ricer;

static VALUE Ricer_run(VALUE self, VALUE app)
{
    return app;
}

void Init_ricer()
{
    Ricer = rb_define_module("Ricer");
    rb_define_singleton_method(Ricer, "run", Ricer_run, 1);
}