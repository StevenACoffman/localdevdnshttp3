### local dev dns for http3

Run a local DNS on UDP 127.0.0.1:8353 so you can use HTTP3 for local development.

This will respond to `http3.dev` DNS Queries with the appropriate DNS A, AAAA, SVCB, and HTTPS records for IP4/IP6 loopback address (localhost).

All other DNS requests made will be proxied to cloudflare 1.1.1.1 over TLS. Code works, but is terrible.

### What? Why?

When you want to run HTTP/3 (QUIC) server over UDP locally, you don't want your client to first make a useless request with TCP
to get the `alt-svc` header to retry it with UDP.

DNS SVCB or HTTPS records (they seem identical to me?) provide a signal so that when your browser asks DNS “where’s the example.com server?” the response mentions “oh BTW it supports HTTP/3” and so the browser goes straight to https://example.com over HTTP/3. Otherwise, first-time visitors will commonly go to http://example.com over HTTP/1.1, and then be redirected to https://example.com over HTTP/1.1 or HTTP/2 (negotiated at TLS handshake time), and only use HTTP/3 on subsequent visits.

For local dev, I don't want to bother running HTTP/2 on TCP.

https://blog.cloudflare.com/speeding-up-https-and-http-3-negotiation-with-dns/

If you are on a mac, and you install [ldns](https://github.com/NLnetLabs/ldns), you can test out this DNS proxy.
```
brew install ldns
drill -p 8353 @127.0.0.1 HTTPS http3.dev
```
Should give you this line:
```
http3.dev 3600 IN HTTPS 1 . alpn="h3,h2" ipv4hint="127.0.0.1" ipv6hint="::1"
```

If you use dig:
```
dig -p 8353 @127.0.0.1 http3.dev -t TYPE65
```
Will give you the less helpful RFC3597 encoded format of the answer:
```
http3.dev.		3600	IN	TYPE65	\# 41 00010000010006026833026832000400047F00000100060010000000 00000000000000000000000001
```


