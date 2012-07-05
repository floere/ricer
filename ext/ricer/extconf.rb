require "mkmf"

$CFLAGS << " -std=c99"

if RUBY_PLATFORM =~ /darwin/
  $DLDFLAGS << " -framework CoreServices"
end

libuv_dir = File.expand_path("../../libuv", __FILE__)
ricer_dir = File.expand_path("../", __FILE__)

system "cd '#{libuv_dir}'; CFLAGS='#{$CFLAGS}' make; cd '#{ricer_dir}'; cp #{libuv_dir}/uv.a #{ricer_dir}/libuv.a"

dir_config "uv", "#{libuv_dir}/include", ricer_dir
have_library "uv"

#dir_config "ricer"
create_makefile "ricer/ricer"