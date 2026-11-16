package chain

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	root, intermediate, leaf *x509.Certificate
	key                      *ecdsa.PrivateKey
	roots                    *x509.CertPool
	now                      time.Time
}

func issue(t *testing.T, template, parent *x509.Certificate, pub any, signer any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func makeFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	rk, ik, lk := key(t), key(t), key(t)
	r := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2}
	root := issue(t, r, r, &rk.PublicKey, rk)
	i := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
	intermediate := issue(t, i, root, &ik.PublicKey, rk)
	l := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IssuingCertificateURL: []string{"https://aia.example/issuer"}}
	leaf := issue(t, l, intermediate, &lk.PublicKey, ik)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return fixture{root, intermediate, leaf, ik, roots, now}
}
func hasIssue(r Result, code string) bool {
	for _, i := range r.Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}
func pemCerts(cs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range cs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}

func TestPresentedChainClassification(t *testing.T) {
	f := makeFixture(t)
	c := checker{roots: f.roots, now: f.now}
	for _, tt := range []struct {
		name       string
		in         []*x509.Certificate
		issues     []string
		wantStatus string
	}{
		{"correct", []*x509.Certificate{f.leaf, f.intermediate}, nil, "ok"},
		{"unordered", []*x509.Certificate{f.intermediate, f.leaf}, []string{"incorrect_order"}, "warning"},
		{"unnecessary root", []*x509.Certificate{f.leaf, f.intermediate, f.root}, []string{"unnecessary_root"}, "warning"},
		{"duplicate", []*x509.Certificate{f.leaf, f.intermediate, f.intermediate}, []string{"duplicate_certificates"}, "warning"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := c.check(context.Background(), tt.in, "", false)
			if r.Status != tt.wantStatus || !r.Verified || !r.Complete {
				t.Fatalf("unexpected result: %+v", r)
			}
			for _, code := range tt.issues {
				if !hasIssue(r, code) {
					t.Errorf("missing %s: %+v", code, r.Issues)
				}
			}
			for i, p := range r.Presented {
				if p.SHA256 != digest(tt.in[i]) {
					t.Fatal("presented order changed")
				}
			}
			out, err := parsePEM([]byte(r.PEM))
			if err != nil || len(out) != 2 || digest(out[0]) != digest(f.leaf) {
				t.Fatalf("incorrect output chain: %v", err)
			}
		})
	}
	r := c.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate}, "example.com", true)
	out, err := parsePEM([]byte(r.PEM))
	if err != nil || len(out) != 3 || digest(out[2]) != digest(f.root) {
		t.Fatal("include root output incorrect", err)
	}
}

func TestExtraCertificate(t *testing.T) {
	f, other := makeFixture(t), makeFixture(t)
	// Subject names are equal, but the key/signature prove which CA belongs to the path.
	r := (&checker{roots: f.roots, now: f.now}).check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, other.intermediate}, "example.com", false)
	if r.Status != "warning" || !r.Verified || !hasIssue(r, "extra_certificates") {
		t.Fatalf("%+v", r)
	}
}

func TestAIAReconstructionFormats(t *testing.T) {
	f := makeFixture(t)
	for name, body := range map[string][]byte{"DER": f.intermediate.Raw, "PEM": []byte(pemCerts(f.intermediate)), "PKCS7": pkcs7(t, f.intermediate), "PKCS7 PEM": pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: pkcs7(t, f.intermediate)})} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c := checker{roots: f.roots, now: f.now, fetch: func(ctx context.Context, u string) ([]byte, error) {
				calls++
				if u != "https://aia.example/issuer" {
					t.Fatal(u)
				}
				return body, nil
			}}
			r := c.check(context.Background(), []*x509.Certificate{f.leaf}, "example.com", false)
			if r.Status != "warning" || !r.Verified || r.Complete || !hasIssue(r, "missing_intermediate") || calls != 1 {
				t.Fatalf("calls=%d result=%+v", calls, r)
			}
			cs, err := parsePEM([]byte(r.PEM))
			if err != nil || len(cs) != 2 {
				t.Fatal("chain did not reconstruct", err)
			}
		})
	}
}

func TestUntrustedSuppliedRootNeverTrusted(t *testing.T) {
	f := makeFixture(t)
	r := (&checker{roots: x509.NewCertPool(), now: f.now}).check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, f.root}, "example.com", true)
	if r.Status != "error" || r.Verified || r.PEM != "" || !hasIssue(r, "untrusted_chain") {
		t.Fatalf("%+v", r)
	}
	c := checker{roots: x509.NewCertPool(), now: f.now, fetch: func(context.Context, string) ([]byte, error) { return []byte(pemCerts(f.intermediate, f.root)), nil }}
	r = c.check(context.Background(), []*x509.Certificate{f.leaf}, "example.com", true)
	if r.Verified || r.PEM != "" {
		t.Fatal("AIA root became trusted")
	}
}

func TestMissingIssuerAndCanceledContext(t *testing.T) {
	f := makeFixture(t)
	calls := 0
	c := checker{roots: f.roots, now: f.now, fetch: func(context.Context, string) ([]byte, error) { calls++; return nil, context.DeadlineExceeded }}
	r := c.check(context.Background(), []*x509.Certificate{f.leaf}, "example.com", false)
	if r.Verified || !hasIssue(r, "missing_issuer") {
		t.Fatalf("%+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	r = c.check(ctx, []*x509.Certificate{f.leaf}, "example.com", false)
	if calls != 0 || !hasIssue(r, "canceled") {
		t.Fatalf("calls=%d result=%+v", calls, r)
	}
}

func TestHostnameAndTimeIndependent(t *testing.T) {
	f := makeFixture(t)
	c := checker{roots: f.roots, now: f.now.Add(48 * time.Hour)}
	r := c.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate}, "wrong.example", false)
	if r.Verified || r.PEM != "" || !hasIssue(r, "expired") || !hasIssue(r, "hostname_mismatch") {
		t.Fatalf("%+v", r)
	}
	c.now = f.now.Add(-2 * time.Hour)
	r = c.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate}, "example.com", false)
	if !hasIssue(r, "not_yet_valid") {
		t.Fatalf("%+v", r)
	}
}

func TestInvalidSignatureAndEKURejected(t *testing.T) {
	f := makeFixture(t)
	lk := key(t)
	bad := *f.leaf
	bad.SerialNumber = big.NewInt(10)
	bad.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	leaf := issue(t, &bad, f.intermediate, &lk.PublicKey, f.key)
	r := (&checker{roots: f.roots, now: f.now}).check(context.Background(), []*x509.Certificate{leaf, f.intermediate}, "example.com", false)
	if r.Verified || !hasIssue(r, "invalid_chain") {
		t.Fatalf("wrong EKU accepted: %+v", r)
	}
	broken := append([]byte(nil), f.leaf.Raw...)
	broken[len(broken)-1] ^= 1
	leaf, err := x509.ParseCertificate(broken)
	if err != nil {
		t.Fatal(err)
	}
	r = (&checker{roots: f.roots, now: f.now}).check(context.Background(), []*x509.Certificate{leaf, f.intermediate}, "example.com", false)
	if r.Verified || r.PEM != "" {
		t.Fatal("invalid signature accepted")
	}
}

func TestPEMInputValidation(t *testing.T) {
	f := makeFixture(t)
	for _, in := range []string{"", "garbage" + pemCerts(f.leaf), pemCerts(f.leaf) + "garbage", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})), strings.Repeat(pemCerts(f.leaf), 33)} {
		if _, err := parsePEM([]byte(in)); err == nil {
			t.Errorf("accepted invalid PEM length %d", len(in))
		}
	}
	if _, err := Check(context.Background(), "example.com", pemCerts(f.leaf), false); err == nil {
		t.Fatal("both modes accepted")
	}
	if _, err := Check(context.Background(), "", "", false); err == nil {
		t.Fatal("empty modes accepted")
	}
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func wrap(t *testing.T, class, tag int, b []byte) []byte {
	return marshal(t, asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: b})
}
func pkcs7(t *testing.T, cs ...*x509.Certificate) []byte {
	var certBytes []byte
	for _, c := range cs {
		certBytes = append(certBytes, c.Raw...)
	}
	version := marshal(t, 1)
	emptySet := []byte{0x31, 0}
	content := wrap(t, 0, 16, marshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}))
	signed := append(version, emptySet...)
	signed = append(signed, content...)
	signed = append(signed, wrap(t, 2, 0, certBytes)...)
	signed = append(signed, emptySet...)
	outer := marshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	outer = append(outer, wrap(t, 2, 0, wrap(t, 0, 16, signed))...)
	return wrap(t, 0, 16, outer)
}

func TestPKCS7Malformed(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, {0x30, 0}, []byte("not a cert")} {
		if _, err := parseIssuerData(b); err == nil {
			t.Errorf("accepted %x", b)
		}
	}
}

func TestNetworkGuardBlocksReservedTunnelAndOwnAddresses(t *testing.T) {
	g := &networkGuard{local: map[netip.Addr]bool{netip.MustParseAddr("8.8.8.8"): true}}
	for _, s := range []string{"0.0.0.0", "127.0.0.1", "10.1.2.3", "100.100.100.100", "169.254.169.254", "172.31.1.1", "192.0.0.9", "192.168.1.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2001::1", "2001:db8::1", "2002:0808:0808::1", "64:ff9b::a00:1", "3fff::1", "8.8.8.8"} {
		if g.allowed(netip.MustParseAddr(s)) {
			t.Errorf("allowed %s", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.4.4", "2606:4700:4700::1111"} {
		if !g.allowed(netip.MustParseAddr(s)) {
			t.Errorf("blocked %s", s)
		}
	}
}

func TestDNSRejectsMixedAnswers(t *testing.T) {
	calls := 0
	g := &networkGuard{local: map[netip.Addr]bool{}, lookup: func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}, nil
	}}
	if _, err := g.resolve(context.Background(), "attacker.example"); err == nil || calls != 1 {
		t.Fatalf("mixed DNS accepted, calls=%d", calls)
	}
	if _, err := g.dial(context.Background(), "tcp", net.JoinHostPort("attacker.example", "443")); err == nil {
		t.Fatal("mixed DNS dial accepted")
	}
}

func TestAIAClientSafety(t *testing.T) {
	g := &networkGuard{local: map[netip.Addr]bool{}, lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	c := g.httpClient()
	defer c.CloseIdleConnections()
	if c.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("proxy enabled")
	}
	for _, u := range []string{"file:///etc/passwd", "ftp://example.com/a", "http://u:p@example.com/a", "http://127.0.0.1/a", "http://attacker.example/a", "http://example.com:8080/a", "https://example.com:8443/a"} {
		if _, err := fetchAIA(context.Background(), c, u); err == nil {
			t.Errorf("accepted unsafe AIA %s", u)
		}
	}
}

func TestHostParsing(t *testing.T) {
	for in, want := range map[string]string{"example.com": "example.com:443", "example.com:8443": "example.com:8443", "[2606:4700::1111]": "[2606:4700::1111]:443", "[2606:4700::1111]:9443": "[2606:4700::1111]:9443", "2606:4700::1111": "[2606:4700::1111]:443"} {
		h, p, err := parseHost(in)
		if err != nil || net.JoinHostPort(h, p) != want {
			t.Errorf("%s: %s %s %v", in, h, p, err)
		}
	}
	for _, in := range []string{"https://example.com", "user@example.com", "example.com:0", "example.com:65536", "example.com:abc", "[::1%eth0]:443", "example.com/path", "example.com?x"} {
		if _, _, err := parseHost(in); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
}

func TestExpiredLeafDoesNotFetchAIA(t *testing.T) {
	f := makeFixture(t)
	calls := 0
	c := checker{roots: f.roots, now: f.now.Add(48 * time.Hour), fetch: func(context.Context, string) ([]byte, error) { calls++; return f.intermediate.Raw, nil }}
	r := c.check(context.Background(), []*x509.Certificate{f.leaf}, "example.com", false)
	if calls != 0 || !hasIssue(r, "expired") {
		t.Fatalf("calls=%d result=%+v", calls, r)
	}
}

func TestDenyIPsConfig(t *testing.T) {
	g := &networkGuard{local: make(map[netip.Addr]bool)}
	if err := g.addDenyIPs("1.1.1.1,2606:4700::1111"); err != nil {
		t.Fatal(err)
	}
	if g.allowed(netip.MustParseAddr("1.1.1.1")) || g.allowed(netip.MustParseAddr("2606:4700::1111")) {
		t.Fatal("configured deny ignored")
	}
	if err := g.addDenyIPs("bad-value"); err == nil {
		t.Fatal("invalid deny config accepted")
	}
}
