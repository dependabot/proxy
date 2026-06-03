package dialer

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDialContextSkipsIPv6WhenUnavailable(t *testing.T) {
	dialer, dialed := testDialer([]string{"2001:db8::1", "192.0.2.1"}, false)

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	require.NoError(t, err)
	require.NotNil(t, conn)

	assert.Equal(t, []string{"192.0.2.1:443"}, *dialed)
}

func TestDialContextUsesIPv6WhenAvailable(t *testing.T) {
	dialer, dialed := testDialer([]string{"2001:db8::1", "192.0.2.1"}, true)

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	require.NoError(t, err)
	require.NotNil(t, conn)

	assert.Equal(t, []string{"[2001:db8::1]:443"}, *dialed)
}

func TestDialContextSkipsIPv4WhenUnavailable(t *testing.T) {
	dialer, dialed := testStackDialer([]string{"2001:db8::1", "192.0.2.1"}, false, true)

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	require.NoError(t, err)
	require.NotNil(t, conn)

	assert.Equal(t, []string{"[2001:db8::1]:443"}, *dialed)
}

func TestDialContextReturnsErrorWhenNeitherFamilyIsAvailable(t *testing.T) {
	dialer, dialed := testStackDialer([]string{"2001:db8::1", "192.0.2.1"}, false, false)

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")

	assert.Nil(t, conn)
	assert.ErrorIs(t, err, ErrNoUsableAddress)
	assert.Empty(t, *dialed)
}

func TestDialContextFiltersByRequestedNetwork(t *testing.T) {
	tests := []struct {
		name    string
		network string
		want    []string
	}{
		{
			name:    "tcp4",
			network: "tcp4",
			want:    []string{"192.0.2.1:443"},
		},
		{
			name:    "tcp6",
			network: "tcp6",
			want:    []string{"[2001:db8::1]:443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer, dialed := testDialer([]string{"2001:db8::1", "192.0.2.1"}, true)

			conn, err := dialer.DialContext(context.Background(), tt.network, "example.com:443")
			require.NoError(t, err)
			require.NotNil(t, conn)

			assert.Equal(t, tt.want, *dialed)
		})
	}
}

func TestDialContextReturnsErrorWhenNoResolvedAddressesAreUsable(t *testing.T) {
	dialer, dialed := testDialer([]string{"2001:db8::1"}, false)

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")

	assert.Nil(t, conn)
	assert.ErrorIs(t, err, ErrNoUsableAddress)
	assert.Empty(t, *dialed)
}

func TestDialContextRejectsBlockedIPsBeforeFilteringByNetwork(t *testing.T) {
	dialer, dialed := testDialer([]string{"::1", "192.0.2.1"}, false)
	dialer.blockedIps = []net.IP{net.ParseIP("::1")}

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")

	assert.Nil(t, conn)
	assert.ErrorIs(t, err, ErrForbiddenRequest)
	assert.Empty(t, *dialed)
}

func testDialer(ips []string, ipv6Available bool) (*Dialer, *[]string) {
	return testStackDialer(ips, true, ipv6Available)
}

func testStackDialer(ips []string, ipv4Available, ipv6Available bool) (*Dialer, *[]string) {
	dialed := []string{}
	dialer := &Dialer{
		resolver: staticResolver{
			ips: ips,
		},
		ipv4Available: func() bool {
			return ipv4Available
		},
		ipv6Available: func() bool {
			return ipv6Available
		},
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			return fakeConn{}, nil
		},
	}
	return dialer, &dialed
}

type staticResolver struct {
	ips []string
}

func (r staticResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return r.ips, nil
}

type fakeConn struct{}

func (fakeConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

func (fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (fakeConn) Close() error {
	return nil
}

func (fakeConn) LocalAddr() net.Addr {
	return fakeAddr("local")
}

func (fakeConn) RemoteAddr() net.Addr {
	return fakeAddr("remote")
}

func (fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type fakeAddr string

func (a fakeAddr) Network() string {
	return string(a)
}

func (a fakeAddr) String() string {
	return string(a)
}
