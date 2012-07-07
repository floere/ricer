# ricer

A Rack-compliant ruby web server. It's written in C cuz its fast.

![sick ride](http://i.imgur.com/HnPbK.jpg)

> *ricer is almost as fast as this car*

### Benchmark

The following Rack app was used benchmark WEBrick, Unicorn, Thin and Ricer:

```ruby
run ->env { [200, { "Content-Type" => "text/html" }, ["hello world"]] }
```

Tests were carried out on a 32 bit Linux VM running in VirtualBox on an Intel Core 2 Quad Q6600.

ApacheBench was used to run the benchmarks with the following options:

    ab -n 1000 -c <...> http://127.0.0.1:3000/

Here are the results:

![science](http://i.imgur.com/IEsUr.png)

