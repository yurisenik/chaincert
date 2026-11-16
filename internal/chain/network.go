package chain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxBody = 2 << 20

var forbidden = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
)

func prefixes(ss ...string) []netip.Prefix {
	p := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		p[i] = netip.MustParsePrefix(s)
	}
	return p
}

type networkGuard struct {
	lookup func(context.Context, string) ([]netip.Addr, error)
	local  map[netip.Addr]bool
}

func newNetworkGuard() (*networkGuard, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("не удалось проверить адреса сетевых интерфейсов: %w", err)
	}
	g := &networkGuard{local: make(map[netip.Addr]bool), lookup: func(ctx context.Context, h string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
	}}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			return nil, errors.New("не удалось проверить адрес сетевого интерфейса")
		}
		g.local[p.Addr().Unmap()] = true
	}
	if err := g.addDenyIPs(os.Getenv("CHAINCERT_DENY_IPS")); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *networkGuard) addDenyIPs(value string) error {
	for _, s := range strings.Split(value, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.Zone() != "" {
			return errors.New("некорректный CHAINCERT_DENY_IPS")
		}
		g.local[a.Unmap()] = true
	}
	return nil
}

func (g *networkGuard) allowed(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.Zone() != "" || g.local[a] {
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, p := range forbidden {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func (g *networkGuard) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		var err error
		addrs, err = g.lookup(ctx, host)
		if err != nil {
			return nil, errors.New("не удалось разрешить DNS-имя")
		}
	}
	if len(addrs) == 0 || len(addrs) > 64 {
		return nil, errors.New("DNS вернул недопустимое число адресов")
	}
	for _, a := range addrs {
		if !g.allowed(a) {
			return nil, errors.New("разрешены только публичные адреса вне сетевых интерфейсов сервера")
		}
	}
	return addrs, nil
}

// Every socket uses an address from the checked DNS response, never a second DNS lookup.
func (g *networkGuard) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("некорректный адрес")
	}
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, a := range addrs {
		c, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, fmt.Errorf("TCP-соединение не установлено: %w", last)
}

func parseHost(input string) (string, string, error) {
	s := strings.TrimSpace(input)
	if s == "" || len(s) > 300 || strings.ContainsAny(s, "/\\@?#% \t\r\n") {
		return "", "", errors.New("укажите имя хоста или хост:порт без URL")
	}
	host, port := s, "443"
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		host = s[1 : len(s)-1]
		if a, err := netip.ParseAddr(host); err != nil || !a.Is6() {
			return "", "", errors.New("некорректный IPv6-адрес")
		}
	} else if strings.HasPrefix(s, "[") || strings.Count(s, ":") == 1 {
		var err error
		host, port, err = net.SplitHostPort(s)
		if err != nil {
			return "", "", errors.New("некорректный хост:порт")
		}
	} else if strings.Contains(s, ":") {
		if _, err := netip.ParseAddr(s); err != nil {
			return "", "", errors.New("некорректный IPv6-адрес")
		}
	}
	if host == "" {
		return "", "", errors.New("пустое имя хоста")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		if len(host) > 253 {
			return "", "", errors.New("слишком длинное имя хоста")
		}
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return "", "", errors.New("используйте DNS-имя в ASCII (для IDN — punycode)")
			}
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("порт должен быть в диапазоне 1–65535")
	}
	return host, strconv.Itoa(n), nil
}

func (g *networkGuard) certificates(ctx context.Context, host, port string) ([]*x509.Certificate, error) {
	c, err := g.dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(8 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	// Verification is performed separately so invalid chains can be diagnosed.
	t := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402
	if err := t.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS-рукопожатие не выполнено: %w", err)
	}
	cs := t.ConnectionState().PeerCertificates
	if len(cs) == 0 || len(cs) > 32 {
		return nil, errors.New("сервер прислал недопустимое число сертификатов")
	}
	total := 0
	for _, c := range cs {
		if len(c.Raw) > 256<<10 || total+len(c.Raw) > maxBody {
			return nil, errors.New("цепочка сертификатов слишком велика")
		}
		total += len(c.Raw)
	}
	return cs, nil
}

func (g *networkGuard) httpClient() *http.Client {
	tr := &http.Transport{Proxy: nil, DialContext: g.dial, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10, MaxConnsPerHost: 2}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("слишком много перенаправлений AIA")
		}
		return checkURL(req.URL)
	}}
}

func checkURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" || len(u.String()) > 4096 {
		return errors.New("недопустимый URL AIA")
	}
	port := u.Port()
	if port != "" {
		if (u.Scheme == "http" && port != "80") || (u.Scheme == "https" && port != "443") {
			return errors.New("AIA допускает только HTTP:80 и HTTPS:443")
		}
	}
	return nil
}

func fetchAIA(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("некорректный URL AIA")
	}
	if err = checkURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Chaincert/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AIA вернул HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, errors.New("ответ AIA слишком велик")
	}
	return b, nil
}
