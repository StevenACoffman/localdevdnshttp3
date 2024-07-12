package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// IpV4AandV6 - there is a better name for this... and I do not know it.
type IpV4AandV6 struct {
	IPV4 string
	IPV6 string
}

// hey, if you come up with a better name, use that
var records = map[string]IpV4AandV6{
	"http3.dev.": {"127.0.0.1", "::1"},
}

type Provider struct {
	serverIPv4 net.IP
	serverIPv6 net.IP
	serverName string
	dohURL     url.URL
}

type DNSHandler struct {
	DnsServer      string
	DnsPort        int
	DnsProtocol    string
	Timeout        int
	DNSClient      *dns.Client
	client         *http.Client
	httpBufferPool *sync.Pool
	udpBufferPool  *sync.Pool
	provider       *Provider
}

func Cloudflare() *Provider {
	return &Provider{
		serverIPv4: net.IP{1, 1, 1, 1},
		serverIPv6: net.IP{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
		serverName: "cloudflare-dns.com",
		dohURL: url.URL{
			Scheme: "https",
			Host:   "cloudflare-dns.com",
			Path:   "/dns-query",
		},
	}
}

func main() {
	provider := Cloudflare()
	ipv6 := false
	serverIP := provider.serverIPv4
	if ipv6 {
		// use IPv6 address by default
		// if both IPv4 and IPv6 are supported.
		serverIP = provider.serverIPv6
	}

	client := newDoTClient(serverIP, provider.serverName)
	const httpTimeout = 3 * time.Second
	client.Timeout = httpTimeout

	httpBufferPool := &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(nil)
		},
	}

	const udpPacketMaxSize = 512
	udpBufferPool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, udpPacketMaxSize)
		},
	}
	// Cloudflare 1.1.1.1 is by default
	protocol := "udp"

	upstream := &DNSHandler{
		DnsServer:      "1.1.1.1",
		DnsPort:        53,
		provider:       provider,
		httpBufferPool: httpBufferPool,
		udpBufferPool:  udpBufferPool,
		client:         client,
	}
	// attach request handler func
	//dns.HandleFunc("service.", upstream.ServeDNS)

	// start server
	port := 8353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: protocol, Handler: upstream}
	log.Printf("Starting at %d\n", port)

	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

//func (handler *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
//	log.Debugf("proxyRequest %+v on server", r)

func (h *DNSHandler) UpstreamServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	buffer := h.udpBufferPool.Get().([]byte)
	// no need to reset buffer as PackBuffer takes care of slicing it down
	wire, err := r.PackBuffer(buffer)
	if err != nil {
		log.Printf("cannot pack message to wire format: %s\n", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}

	respWire, err := h.requestHTTP(context.Background(), wire)

	// It's fine to copy the slice headers as long as we keep
	// the underlying array of bytes.
	h.udpBufferPool.Put(buffer) //nolint:staticcheck

	if err != nil {
		log.Printf("HTTP request failed: %s\n", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}

	message := new(dns.Msg)
	if err := message.Unpack(respWire); err != nil {
		log.Printf("cannot unpack message from wireformat: %s\n", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}

	message.SetReply(r)
	if err := w.WriteMsg(message); err != nil {
		log.Printf("write dns message error: %s\n", err)
	}
}
func (h *DNSHandler) requestHTTP(ctx context.Context, wire []byte) (respWire []byte, err error) {
	buffer := h.httpBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer h.httpBufferPool.Put(buffer)
	_, err = buffer.Write(wire)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.provider.dohURL.String(), buffer)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/dns-udpwireformat")
	response, err := h.client.Do(request)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrHTTPStatus, response.Status)
	}

	respWire, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	return respWire, nil
}

var (
	ErrHTTPStatus = errors.New("bad HTTP status")
)

func (d *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	for _, question := range r.Question {
		fmt.Println("Question: ", question.String())
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	var resp *dns.Msg
	var err error

	switch r.Opcode {
	case dns.OpcodeQuery:
		resp, err = d.parseQuery(m)
		if err != nil {
			log.Printf("%+v\n", err)
		}
	}
	if len(resp.Answer) == 0 {
		log.Println("No local answers")
		d.UpstreamServeDNS(w, r)
	} else {
		w.WriteMsg(resp)
	}
}

func (d *DNSHandler) parseQuery(m *dns.Msg) (*dns.Msg, error) {
	// populate local alias Question answers
	for _, q := range m.Question {
		ip, ok := records[q.Name]
		if ok {
			_, err := localLoopBackHTTP3(m, q, ip)
			if err != nil {
				return m, err
			}
		}
	}
	log.Printf("%+v\n", "No local errors")
	return m, nil
}

func (d *DNSHandler) Exchange(msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	return d.DNSClient.Exchange(msg, fmt.Sprintf("%s:%d", d.DnsServer, d.DnsPort))
}

func localLoopBackHTTP3(m *dns.Msg, q dns.Question, ip IpV4AandV6) (*dns.Msg, error) {
	switch q.Qtype {
	case dns.TypeHTTPS:
		log.Printf("Query for Type HTTPS for %s\n", q.Name)
		rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN HTTPS 1 . alpn=\"h3,h2\" ipv4hint=\"%s\" ipv6hint=\"%s\"", q.Name, ip.IPV4, ip.IPV6))
		if err != nil {
			log.Printf("unable to create RR for %s %+v\n", q.Name, err)
			return m, err
		}
		m.Answer = append(m.Answer, rr)

	case dns.TypeSVCB:
		log.Printf("Query for Type SVCB for %s\n", q.Name)
		rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN SVCB 1 . alpn=\"h3,h2\" ipv4hint=\"%s\" ipv6hint=\"%s\"", q.Name, ip.IPV4, ip.IPV6))
		if err != nil {
			log.Printf("unable to create RR for %s %+v\n", q.Name, err)
			return m, err
		}
		m.Answer = append(m.Answer, rr)

	case dns.TypeA:
		log.Printf("Query for Type A for %s\n", q.Name)
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip.IPV4))
		if err != nil {
			log.Printf("unable to create RR for %s %+v\n", q.Name, err)
			return m, err
		}
		m.Answer = append(m.Answer, rr)

	case dns.TypeAAAA:
		log.Printf("Query for Type AAAA for %s\n", q.Name)
		rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip.IPV6))
		if err != nil {
			log.Printf("unable to create RR for %s %+v\n", q.Name, err)
			return m, err
		}
		m.Answer = append(m.Answer, rr)
	default:
		log.Printf("Query for Unknown Type %v for %s\n", q.Qtype, q.Name)
	}
	return m, nil
}

func newDoTClient(serverIP net.IP, serverName string) *http.Client {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{
		Resolver: newOpportunisticDoTResolver(serverIP, serverName),
	}
	httpTransport.DialContext = dialer.DialContext
	return &http.Client{
		Transport: httpTransport,
	}
}

func newOpportunisticDoTResolver(serverIP net.IP, serverName string) *net.Resolver {
	const dialerTimeout = 5 * time.Second
	dialer := &net.Dialer{
		Timeout: dialerTimeout,
	}

	plainAddr := net.JoinHostPort(serverIP.String(), "53")
	tlsAddr := net.JoinHostPort(serverIP.String(), "853")

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, "tcp", tlsAddr)
			if err != nil {
				// fallback on plain DNS if DoT does not work
				return dialer.DialContext(ctx, "udp", plainAddr)
			}
			return tls.Client(conn, tlsConf), nil
		},
	}
}

func ipVersionsSupported(ctx context.Context) (ipv4, ipv6 bool) {
	dialer := &net.Dialer{}
	_, err := dialer.DialContext(ctx, "tcp4", "127.0.0.1:0")
	ipv4 = err.Error() == "dial tcp4 127.0.0.1:0: connect: connection refused"
	_, err = dialer.DialContext(ctx, "tcp6", "[::1]:0")
	ipv6 = err.Error() == "dial tcp6 [::1]:0: connect: connection refused"
	return ipv4, ipv6
}
