require "rake/extensiontask"

Rake::ExtensionTask.new "ricer"

task :default => :compile

task :clean do
  Dir.chdir File.expand_path("../ext/ricer", __FILE__)
  system "rm -f *.o *.bundle *.a Makefile"
end

task :irb => :compile do
  system "ruby -I./lib -rricer -rirb -e 'IRB.start' -- --simple-prompt"
end