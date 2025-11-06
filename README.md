# cldaproxy

`cldaproxy` proxies Connection-less LDAP (CLDAP), which uses UDP as its
transport, over normal LDAP, which uses TCP. This is useful for Red Teaming
operations where the Red Teamer uses a Windows VM transparently connected to the
target network through SOCKS, as described in @bitsadmin's
[Living Off the Foreign Land (LOFL)](https://github.com/bitsadmin/lofl).

`cldaproxy` replaces the `cldaproxy.sh` script from the repository mentioned
above. The main difference in this implementation is support for transparent
proxying ([`TPROXY`](https://www.kernel.org/doc/html/latest/networking/tproxy.html)).
Transparent proxying allows the proxy to be universal, meaning that it doesn't
need to be aware of the addresses of the LDAP servers. It can proxy for
multiple domains simultaneously.

## How to use

### Getting `cldaproxy`

#### Dependencies
* Go >= 1.24

#### Install

Use `go install` to install `cldaproxy` to your `GOPATH`.

```sh
go install github.com/wfdewith/cldaproxy/cmd/cldaproxy@latest
```

#### Build from source

Clone the source code.

```sh
git clone https://github.com/wfdewith/cldaproxy
```

Build the binary.

```sh
go build -o . ./...
```

### Running

#### Routing tables

Create a policy for packets the firewall mark to use a separate routing table
and add a default route to loopback in this table with the following commands.

```sh
ip rule add fwmark 0xc1dab lookup 100
ip route add local default dev lo table 100
```

#### Firewall

In the examples below, 10.1.0.0/16 and 10.2.0.0/16 are target networks for which
CLDAP should be proxied.

For `iptables`, use the following command.

```sh
iptables -t mangle -A PREROUTING -d 10.1.0.0/16,10.2.0.0/16 -p udp --dport 389 -j TPROXY --tproxy-mark 0xc1dab/0xc1dab --on-port 3890
```

For `nftables`, you can use the following commands.

```sh
nft add table ip proxy
nft add chain proxy divert '{ type filter hook prerouting priority mangle; }'
nft add rule proxy divert 'ip daddr { 10.1.0.0/16, 10.2.0.0/16 } udp dport 389 tproxy to :3890 meta mark set 0xc1dab accept'
```

#### Running `cldaproxy`

Note that `cldaproxy` needs at least the `CAP_NET_ADMIN` capability.

```sh
cldaproxy
```

See `cldaproxy -h` for configurable options. Note that the listening port must
match the target port in the firewall rules above.

## Comparison to `cldaproxy.sh`

The `cldaproxy.sh` script uses a destination NAT (DNAT) `iptables` rule with the
`REDIRECT` target. This DNAT rule redirects all CLDAP traffic to known Domain
Controllers to the loopback interface (127.0.0.1). When the kernel executes this
rule for a packet, it rewrites the destination IP address and port in the packet
to the redirect target. For UDP specifically, it is not possible to retrieve the
original destination IP and port (it is possible for TCP[^1]).

[^1]: TCP creates a new socket for every accepted connection. You can call
  `getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST, ...)` on this socket to retrieve
  the original destination from the conntrack table in the kernel. In contrast,
  UDP is connectionless, so the kernel does not keep track of UDP in the
  conntrack table and there is no connection socket to call `getsockopt` on.

`cldaproxy.sh` simply ignores the original destination and forwards all messages
to a single LDAP server through `socat`. It finds this LDAP server by finding
all LDAP servers in the domain through the DNS SRV record and selecting the
first one. This means that one instance of `cldaproxy.sh` can only support a
single domain. It also means that starting `cldaproxy.sh` is dependent on
functional DNS to the target network.

In contrast, `cldaproxy` uses the `TPROXY` target and an alternative routing
table that redirects all CLDAP traffic (that is: UDP on port 389) to the
loopback interface. This causes all packets to arrive with their original
destination IP address and port intact. The original destination can be
retrieved through ancillary data (see `recvmsg(3)`). `cldaproxy` does not
depend on DNS when starting, because it only deals with IP addresses. The
Windows LOFL VM is responsible for resolving the target LDAP server.

When `cldaproxy` receives a packet, it will retrieve its original destination
and then set up a TCP connection to this destination and forward the packet
contents. `cldaproxy` will then wait for the response on the TCP connection and
finally send the response data back to the UDP source.
