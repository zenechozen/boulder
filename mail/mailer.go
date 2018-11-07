package mail

import (
	"crypto/tls"
	"net"
)

func Dial() (server, port string) (net.Conn, error) {
	hostport := net.JoinHostPort(di.server, di.port)
	var conn net.Conn
	var err error
	conn, err = tls.Dial("tcp", hostport, &tls.Config{
		InsecureSkipVerify: true,
	})
	
	return conn, err
}
