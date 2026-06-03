package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/rs/dnscache"
)

// ErrForbiddenRequest is returned when a request is made to a blocked IP.
var ErrForbiddenRequest = errors.New("forbidden")

// ErrNoUsableAddress is returned when DNS resolution succeeds but none of the
// returned addresses can be used for the requested network.
var ErrNoUsableAddress = errors.New("no usable address")

type hostResolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dialer is a wrapper around net.Dialer that uses a dnscache.Resolver to cache DNS lookups.
type Dialer struct {
	net.Dialer
	resolver      hostResolver
	blockedIps    []net.IP
	dialContext   dialContextFunc
	ipv4Available func() bool
	ipv6Available func() bool
}

// New creates a new Dialer.
func New(resolver *dnscache.Resolver, blockedIps []net.IP) *Dialer {
	return &Dialer{
		Dialer: net.Dialer{
			Control: safeControl(blockedIps),
		},
		resolver:      resolver,
		blockedIps:    blockedIps,
		ipv4Available: defaultIPv4Available,
		ipv6Available: defaultIPv6Available,
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
	ips, err = d.usableIPs(network, host, ips)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		conn, err = d.dial(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			break
		}
	}
	return
}

func (d *Dialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.dialContext != nil {
		return d.dialContext(ctx, network, address)
	}
	return d.Dialer.DialContext(ctx, network, address)
}

func (d *Dialer) usableIPs(network, host string, ips []string) ([]string, error) {
	usable := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			usable = append(usable, ip)
			continue
		}

		if d.isBlockedIP(parsedIP) {
			return nil, ErrForbiddenRequest
		}

		if !d.usableNetworkIP(network, parsedIP) {
			continue
		}

		usable = append(usable, ip)
	}

	if len(usable) == 0 && len(ips) > 0 {
		return nil, fmt.Errorf("%w: %s has no addresses usable on %s", ErrNoUsableAddress, host, network)
	}

	return usable, nil
}

func (d *Dialer) usableNetworkIP(network string, ip net.IP) bool {
	isIPv4 := ip.To4() != nil
	switch network {
	case "tcp4":
		return isIPv4
	case "tcp6":
		return !isIPv4
	case "tcp":
		return (isIPv4 && d.supportsIPv4()) || (!isIPv4 && d.supportsIPv6())
	default:
		return true
	}
}

func (d *Dialer) supportsIPv4() bool {
	if d.ipv4Available == nil {
		return defaultIPv4Available()
	}
	return d.ipv4Available()
}

func (d *Dialer) supportsIPv6() bool {
	if d.ipv6Available == nil {
		return defaultIPv6Available()
	}
	return d.ipv6Available()
}

func (d *Dialer) isBlockedIP(ip net.IP) bool {
	for _, blockedIP := range d.blockedIps {
		if ip.Equal(blockedIP) {
			return true
		}
	}
	return false
}

var (
	ipv4AvailabilityOnce sync.Once
	ipv4Availability     bool
	ipv6AvailabilityOnce sync.Once
	ipv6Availability     bool
)

// defaultIPv4Available reports whether the host can route IPv4 traffic. It
// probes once and caches the result, since IPv4 availability won't change
// while the process is running.
func defaultIPv4Available() bool {
	ipv4AvailabilityOnce.Do(func() {
		ipv4Availability = checkConnectivity("udp4", "192.0.2.1:80")
	})
	return ipv4Availability
}

// defaultIPv6Available reports whether the host can route IPv6 traffic. It
// probes once and caches the result, since IPv6 availability won't change
// while the process is running.
func defaultIPv6Available() bool {
	ipv6AvailabilityOnce.Do(func() {
		ipv6Availability = checkConnectivity("udp6", "[2001:db8::1]:80")
	})
	return ipv6Availability
}

func checkConnectivity(network, address string) bool {
	// A connected UDP dial sends no packets; it just asks the kernel to pick a
	// route. That returns fast when the address family is disabled or has no
	// route, as in single-stack Docker environments.
	conn, err := net.DialTimeout(network, address, 100*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

type control func(network, address string, conn syscall.RawConn) error

func safeControl(blockedIps []net.IP) control {
	return func(network string, address string, conn syscall.RawConn) error {
		if network != "tcp4" && network != "tcp6" {
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
