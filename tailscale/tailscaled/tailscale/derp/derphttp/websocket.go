// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || windows || linux || darwin

package derphttp

import (
	"context"
	"log"
	"net"
	"net/http"

	"github.com/coder/websocket"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/net/wsconn"
)

const canWebsockets = true

var httpClient *http.Client

func init() {
	dialWebsocketFunc = dialWebsocket

	transport := &http.Transport{
		Proxy: tshttpproxy.ProxyFromEnvironment,
	}
	httpClient = &http.Client{
		Transport: transport,
	}
	tshttpproxy.SetTransportGetProxyConnectHeader(transport)
}

func dialWebsocket(ctx context.Context, urlStr string) (net.Conn, error) {

	c, res, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		Subprotocols: []string{"derp"},
		HTTPClient:   httpClient,
	})
	if err != nil {
		log.Printf("websocket Dial: %v, %+v", err, res)
		return nil, err
	}
	log.Printf("websocket: connected to %v", urlStr)
	netConn := wsconn.NetConn(context.Background(), c, websocket.MessageBinary, urlStr)
	return netConn, nil
}
