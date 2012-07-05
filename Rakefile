require "rake/extensiontask"

Rake::ExtensionTask.new "ricer"

task :default => :compile

task :irb => :compile do
  system "ruby -I./lib -rricer -rirb -e 'IRB.start' -- --simple-prompt"
end