perl-tcp-proxy
----------------

Name
=====

    perl-tcp-proxy - a TCP proxy in Perl for various testing purpose.

Description
============

    This proxy is useful for various network-related tests. It's capable
    to listen on a local port and relay all traffic on it to certain
    remote or local address/port. Some advance feature can be tune in
    source at present:

        * Split upstream packet into segment before relaying and vice versa.

        * Specify delays in forward/backward traffic relaying (delays are
          inserted every N bytes).
        
        * Force connection closing after forward/backward relaying traffic
          reached certain threshold (in bytes).

Synopsis
=========

    ptcproxy <local port> [<remote address>:]<remote port>

Authors
=========

    flygoast <flygoast@126.com>

See Also
=========

    etcproxy (https://github.com/chaoslawful/etcproxy)
