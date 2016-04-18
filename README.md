# reicec
A simple ICE client for testing

# Dependencies
You need to install libre and https://github.com/alfredh/rew first.

# Building
```
$ make
```

# Usage

```
alfredh@debian:~/git/reicec$ ./reicec -h
Usage: reicec [-s|-c <host>] [options]
       reicec [-h]

Client/Server:
	-c <host>   Run in client mode, connecting to <host>
	-s          Run in Server mode

Candidates options:
	-u          Enable UDP candidates
	-t          Enable TCP candidates
	-4          Enable IPv4 candidates
	-6          Enable IPv6 candidates
	-i <if>     Bound to only this interface
	-S <STUN>   Enable SRFLX from this STUN-server
	-T <TURN>   Enable RELAY/SRFLX from this TURN-server
	-U <user>   TURN username
	-P <pass>   TURN password
	-L          Include local and link-local addresses

Miscellaneous:
	-C          Force running ICE checklist
	-p          Checklist pacing interval (milliseconds)
	-D          Enable ICE debugging
	-X          Enable ICE packet tracing
	-h          Print this message and quit
	-w          Wait forever, do not quit

All possible candidates are enabled by default

```
