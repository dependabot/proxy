package dialer

import (
	"context"
	"errors"
	"fmt"
	"github.com/rs/dnscache"
	"net"
	"syscall"
)

// ErrForbiddenRequest is returned when a request is made to a blocked IP.
var ErrForbiddenRequest = errors.New("forbidden")

// Dialer is a wrapper around net.Dialer that uses a dnscache.Resolver to cache DNS lookups.
type Dialer struct {
	net.Dialer
	resolver *dnscache.Resolver
}

// New creates a new Dialer.
func New(resolver *dnscache.Resolver, blockedIps []net.IP) *Dialer {
	return &Dialer{
		Dialer: net.Dialer{
			Control: safeControl(blockedIps),
		},
		resolver: resolver,
	}
}

// Dial specifies the dial function for creating unencrypted TCP connections.
//
// Go doesn't have vtables, so I think we have to specify this calls the new DialContext?
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext dials... with context.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := d.resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		conn, err = d.Dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			break
		}
	}
	return
}

type control func(network, address string, conn syscall.RawConn) error

func safeControl(blockedIps []net.IP) control {
	return func(network string, address string, conn syscall.RawConn) error {
		if !(network == "tcp4" || network == "tcp6") {
			return fmt.Errorf("%s is not a safe network type", network)
		}

		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%s is not a valid host/port pair: %w", address, err)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("%s is not a valid IP address", host)
		}

		for _, blockedIP := range blockedIps {
			if ip.Equal(blockedIP) {
				return ErrForbiddenRequest
			}
		}

		return nil
	}
}
