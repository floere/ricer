require "mkmf"

$CFLAGS << " -std=c99"

create_makefile "ricer/ricer"