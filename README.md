# RingSocket
High Performance Lockless Multi-threaded Linux WebSocket Server in C11 for Dynamic Backend App Embedding

[todo]

## Table of contents
* [Installation](#installation)
* [Configuration](#configuration)
* [Usage](#usage)
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

## Configuration
All configuration options are expected to be specified in a `ringsocket.json` JSON file, by default expected to be located at `\etc\ringsocket.json`.

[todo]

## Usage
[todo]

## Todo
Even the todo itself is a [todo]...

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
