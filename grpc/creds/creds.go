package creds

import (
	"crypto/tls"
	"net"
)

// serverTransportCredentials is a grpc/credentials.TransportCredentials which supports
// filtering acceptable peer connections by a list of accepted client certificate SANs
type serverTransportCredentials struct {
	serverConfig *tls.Config
}
	
// ServerHandshake does the authentication handshake for servers. It returns
// the authenticated connection and the corresponding auth information about
// the connection.
func (tc *serverTransportCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, error) {
	// Perform the server <- client TLS handshake. This will validate the peer's
	// client certificate.
	conn := tls.Server(rawConn, tc.serverConfig)
	if err := conn.Handshake(); err != nil {
		return nil, err
	}

	return conn, nil
}
