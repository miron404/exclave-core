package masque

import (
	"net/http"

	"github.com/exclavenetwork/exclave-core/v5/proxy/masque/internal/connectip"
)

type connectipConn struct {
	*connectip.Conn
	resp *http.Response
}

func (c *connectipConn) Close() error {
	c.resp.Body.Close()
	return c.Conn.Close()
}
