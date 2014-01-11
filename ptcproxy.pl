#!/usr/bin/perl
#======================================================================
# I forked it, then heavily changed it, and added some feature ported 
# from a tcp proxy in Erlang[https://github.com/chaoslawful/etcproxy].
#
# Feng Gu <flygoast@126.com>
#======================================================================

use warnings;
use strict;
use Data::Dumper;
use POSIX qw(:sys_wait_h :signal_h);
use IO::Socket;

use constant    DOWNSTREAM => 0;
use constant    UPSTREAM => 1;

my $VERSION = "0.0.3";

#===================================================================
# Options you can tune. I'll put them in command options someday.
#===================================================================
my @allowed_ips = ('1.2.3.4', '5.6.7.8', '127.0.0.1', '192.168.1.2');
my $debug = 1;

# whether split packet from downstream
my $split_downstream = 1;
# segment length when splitting packet from downstream
my $segment_downstream = 30;
# dalay inserted between splitted segments from downstream
my $delay_downstream = 1;
# whether split packet from upstream
my $split_upstream = 1;
# segment length when splitting packet from upstream
my $segment_upstream = 10;
# dalay inserted between splitted segments from upstream
my $delay_upstream = 1;
# close connection after sent N bytes of traffic from downstream
my $close_after_downstream = 0;
# close connection after setn N bytes of traffic from upstream
my $close_after_upstream = 0;

my $local_addr;
my $local_port;
my $remote_addr;
my $remote_port;

main();

sub main {
    if (@ARGV != 2) {
        usage();
        exit(1);
    }

    $SIG{PIPE} = sub { dbg("*** [ALERT] client connection closed ***"); };
    $SIG{CHLD} = sub { 
        for ( ; ; ) {
            my $pid = waitpid(-1, WNOHANG);
            return if ($pid == 0 || $pid == -1);
        }
    };

    $local_addr = "0.0.0.0";
    $local_port = $ARGV[0];

    if ((my $pos = index($ARGV[1], ":")) >= 0) {
        $remote_addr = substr($ARGV[1], 0, $pos);
        $remote_port = substr($ARGV[1], $pos + 1);
    } else {
        $remote_addr = "0.0.0.0";
        $remote_port = $ARGV[1];
    }

    dbg("#$local_addr:$local_port ==> $remote_addr:$remote_port");

    my $server = new_server($local_addr, $local_port);

    while (1) {
        my $socket = $server->accept();
        next unless defined($socket);
        my ($client_ip, $client_port) = client_info($socket);
        my $conn_addr = inet_ntoa($socket->sockaddr);
        dbg("*** $client_ip:$client_port <=> #$conn_addr:$local_port ***");

        unless (client_allowed($client_ip)) {
            dbg("*** connection from $client_ip denied ***");
            $socket->close;
            next;
        }
    
        if ((my $pid = fork()) == 0) {
            $server->close;    
            my $remote = new_upstream_conn($remote_addr, $remote_port);
            my $buffer;
            my $quit = 0;

            while (1) {
                my $read;

                while (1) {
                    $read = $socket->sysread($buffer, 4096);
                    if (!defined($read)) {
                        die "*** [$$] read from downstream failed: $! ***\n";
                    }

                    if ($read == 0) {
                        dbg("*** connection from downstream closed ***");
                        $quit = 1;
                        last;
                    }

                    if (relay_downstream_packet($remote, $buffer) < 0) {
                        die "[$$] relay packet from downstream failed\n";
                    }

                    if ($read == 4096) {
                        next;
                    }

                    last;
                }

                if ($quit) {
                    $socket->close;
                    $remote->close;
                    dbg("*** [$$] exit ***");
                    exit(0);
                }

                while (1) {
                    $read = $remote->sysread($buffer, 4096);
                    if (!defined($read)) {
                        die "[$$] read from upstream failed: $!\n";
                    }

                    if ($read == 0) {
                        dbg("*** connection from upstream closed ***");
                        $quit = 1;
                        last;
                    }

                    if (relay_upstream_packet($socket, $buffer) < 0) {
                        die "[$$] relay packet from upstream failed\n";
                    }

                    if ($read == 4096) {
                        next;
                    }

                    last;
                }

                if ($quit) {
                    $socket->close;
                    $remote->close;
                    dbg("*** [$$] exit ***");
                    exit(0);
                }
            }
            exit(0);
        } elsif ($pid < 0) {
            die "fork failed\n";
        }

        $socket->close;
    }
}

sub relay_downstream_packet {
    my ($remote, $buffer) = @_;
    my @segments;

    if ($split_downstream) {
        if ($segment_downstream == 0 || $segment_downstream == 1) {
            @segments = split(//, $buffer);
        } else {
            while (length($buffer) > $segment_downstream) {
                push @segments, substr($buffer, 0, $segment_downstream);
                $buffer = substr($buffer, $segment_downstream);
            }
            push @segments, $buffer;
        }

        my $bytes_sent = 0;
        foreach my $seg (@segments) {
            return -1 unless $remote->syswrite($seg);
            dbg(">>> Proxy " . length($seg) . " from downstream to upstream");

            $bytes_sent += length($seg);

            if ($close_after_downstream
                    && $bytes_sent >= $close_after_downstream) {
                return -1;
            }

            if ($delay_downstream) {
                sleep($delay_downstream);
            }
        }
    } else {
        return -1 unless $remote->syswrite($buffer);
        dbg(">>> Proxy " . length($buffer) . " from downstream to upstream");
    }
    return 0;
}

sub relay_upstream_packet {
    my ($remote, $buffer) = @_;
    my @segments;

    if ($split_upstream) {
        if ($segment_upstream == 0 || $segment_upstream == 1) {
            @segments = split(//, $buffer);
        } else {
            while (length($buffer) > $segment_upstream) {
                push @segments, substr($buffer, 0, $segment_upstream);
                $buffer = substr($buffer, $segment_upstream);
            }
            push @segments, $buffer;
        }

        my $bytes_sent = 0;
        foreach my $seg (@segments) {
            return -1 unless $remote->syswrite($seg);
            dbg("<<< Proxy " . length($seg) . " from upstream to downstream");

            $bytes_sent += length($seg);

            if ($close_after_upstream
                    && $close_after_upstream >= $bytes_sent) {
                return -1;
            }

            if ($delay_upstream) {
                sleep($delay_upstream);
            }
        }
    } else {
        return -1 unless $remote->syswrite($buffer);
        dbg("<<< Proxy " . length($buffer) . " from upstream to downstream");
    }
    return 0;
}

sub new_upstream_conn {
    my ($host, $port) = @_;

    return IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        NoDelay => 1
    ) || die "Unable to connect to $host:$port: $!";
}

sub new_server {
    my ($host, $port) = @_;
    my $server = IO::Socket::INET->new(
        LocalAddr => $host,
        LocalPort => $port,
        ReuseAddr => 1,
        Listen    => 100
    ) || die "Unable to listen on $host:$port: $!";
}

sub client_info {
    my $client = shift;
    return (inet_ntoa($client->peeraddr), $client->peerport);
}

sub client_allowed {
    my $client_ip = shift;
    return grep { $_ eq $client_ip } @allowed_ips;
}

sub usage {
    print "usage: ptcproxy <local port> [<remote address>:]<remote port>\n";
    print "version: $VERSION\n";
}

sub dbg {
    print "@_", "\n" if $debug;
}
