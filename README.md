# RingSocket
RingSocket is a highly scalable WebSocket server for Linux written in C (C11) with features and characteristics such as:
* Completely lockless multi-threaded architecture consisting of worker threads and dedicated app threads
* Fully event-based: epoll loops for workers, and futex loops for apps
* App plugin functionality allowing rapid modular backend integration with very low performance overhead.
* 100% compliance with the WebSocket standard: RFC1234567890
* EBPF blah blah
* Best security practises

Planned features include:
* app language ports: write apps in other languages such as Python, embedded ar compile-time directly into the app DLL

[todo]

## Table of contents
* [Installation](#installation)
* [Control flow overview](#control-flow-overview)
  * [Startup](#startup)
  * [Worker threads](#worker-threads)
  * [App threads](#app-threads)
* [Creating a RingSocket app](#creating-a-ringsocket-app)
* [Configuration](#configuration)
* [Todo](#todo)
* [Contributing](#contributing)
* [Email me](#email-me)

## Installation
Aside from needing a fairly recent Linux kernel and C compiler, RingSocket has only 2 external dependencies: OpenSSL and [Jgrandson](https://github.com/wbudd/jgrandson/blob/master/src/jgrandson.h). Make sure these are installed first, then proceed with something like this:

    git clone https://github.com/wbudd/ringsocket.git
    cd ringsocket
    make
    sudo make install

Note that if not already present, `make install` will (attempt to) create an unprivileged system user named `ringsock` for exclusive use by the RingSocket daemon.

## Control flow overview
### Startup
1. The RingSock binary is executed as a user with sufficient privileges/capabilities (e.g., root).
1. The process switches to running as user `ringsock` (see "Installation" above).
1. All capabilities are removed except those needed for configuration purposes.
1. The process daemonizes (double `fork()`, closing of std streams, etc).
1. The configuration file is parsed (see "Configuration" below).
1. Resource limits are set.
1. Network ports on which to listen for incoming WebSocket traffic are opened.
1. Each app DLL (`.so` file) specified in the configuration file is loaded with `dlopen()`.
1. All remaining capabilities are removed.
1. Worker threads and dedicated app threads are spawned.
### Worker threads
[todo] stub:
create tls contexts
listen to sockets
loop over epoll events with `epoll_wait()`:
    accept new incoming sockets
    handle peer events:
	* if new and on encryped port: TLS handshake
    * if connection not yet upgraded to WebSocket: handle upgrade from HTTP
    * if received WebSocket data from peer: send that data to destination app
    * if write availability notification: resuming sending data to ws client
    receive eventds from apps:
    * receive data from corresponding app, and send it to all recipient ws clients
### App threads
loop over futex waits:
    awake on futex wakes from workers
    receive data from workers
    call relevant app callback
    send data written out from callback to relevant workers 

## Creating a RingSocket app
[todo]

## Configuration
All configuration options are expected to be specified in a `ringsocket.json` JSON file, at `\etc\ringsocket.json` by default.

[todo]

## Todo
* Fill in the [todo] parts of this README.md
* Move wref stuff out of `rs_ring.c` into a separate `rs_wref.c`
* Replace randomizing BPF with cpu affinity-based EBPF
* Reduce thread_local usage in favor of stack variables to optimize performance
* Add/improve comments for the lesser documented parts of the codebase

## Contributing
Pull requests and other contributions are always welcome! License: [MIT](https://github.com/wbudd/jgrandson/blob/master/LICENSE).

## Email me
Feel free to send me email at the address below, *especially* if you might be interested in offering me employment or contractual work. Based in Osaka, Japan; but also happy to work remotely.

           _               _               _     _                   
          | |             | |             | |   | |                  
     _ _ _| |__      _ _ _| |__  _   _  __| | __| |  ____ ___  ____  
    | | | |  _ \    | | | |  _ \| | | |/ _  |/ _  | / ___) _ \|    \ 
    | | | | |_) ) @ | | | | |_) ) |_| ( (_| ( (_| |( (__| |_| | | | |
     \___/|____/     \___/|____/|____/ \____|\____(_)____)___/|_|_|_|
（日本語能力試験N1を取得／永住者の在留資格あり）
