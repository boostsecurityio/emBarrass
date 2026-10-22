// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Older Node releases do not honor HTTPS_PROXY automatically. Establish only
// the proxy tunnel explicitly, leaving certificate verification to Node TLS.
const http = require('http');
const tls = require('tls');
const target = new URL(process.argv[2]);
const proxy = new URL(process.env.HTTPS_PROXY);
const credentials = decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password);
const request = http.request({
  hostname: proxy.hostname,
  port: proxy.port,
  method: 'CONNECT',
  path: target.host + ':443',
  agent: false,
  headers: { 'Proxy-Authorization': 'Basic ' + Buffer.from(credentials).toString('base64') },
});

request.on('error', () => { process.exitCode = 1; });
request.on('connect', (response, socket) => {
  if (response.statusCode !== 200) {
    socket.destroy();
    process.exitCode = 1;
    return;
  }
  const client = tls.connect({ socket, servername: target.hostname }, () => {
    client.end('HEAD / HTTP/1.1\r\nHost: ' + target.host + '\r\nConnection: close\r\n\r\n');
  });
  client.on('error', () => { process.exitCode = 1; });
  client.resume();
});
request.end();
