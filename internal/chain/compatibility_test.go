package chain

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func assertExportedPath(t *testing.T, output string, expected []*x509.Certificate, root *x509.Certificate, nowChecker checker) {
	t.Helper()
	actual, err := parsePEM([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("exported %d certificates, expected %d", len(actual), len(expected))
	}
	for i, cert := range actual {
		if digest(cert) != digest(expected[i]) {
			t.Fatalf("wrong certificate at index %d", i)
		}
	}
	// Revalidate the exported chain against only the advertised alternate root.
	// A preferred system root must not mask a missing compatibility certificate.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	nowChecker.roots = roots
	if _, err := nowChecker.verify(actual[0], actual); err != nil {
		t.Fatalf("export does not verify to its advertised root: %v", err)
	}
}

func TestCompatibilityExportHostAndPEMIncludeRoot(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	c := checker{roots: f.roots, now: f.now}
	input := []*x509.Certificate{f.leaf, f.intermediate, f.cross}
	for _, source := range []string{"host", "PEM"} {
		for _, includeRoot := range []bool{false, true} {
			t.Run(source+map[bool]string{false: " without root", true: " with root"}[includeRoot], func(t *testing.T) {
				certs := input
				host := "example.com"
				if source == "PEM" {
					var err error
					certs, err = parsePEM([]byte(pemCerts(input...)))
					if err != nil {
						t.Fatal(err)
					}
					host = ""
				}
				r := c.check(context.Background(), certs, host, includeRoot)
				if !r.Verified || len(r.CompatibilityChains) != 1 || r.CompatibilityChains[0].Root != caLabel(f.alternateRoot) {
					t.Fatalf("%+v", r)
				}
				expected := []*x509.Certificate{f.leaf, f.intermediate, f.cross}
				if includeRoot {
					expected = append(expected, f.alternateRoot)
				}
				assertExportedPath(t, r.CompatibilityChains[0].PEM, expected, f.alternateRoot, c)
				baseline := c.check(context.Background(), input[:2], host, includeRoot)
				if baseline.PEM != r.PEM {
					t.Fatal("preferred export changed")
				}
			})
		}
	}
}

func TestCompatibilityExportOnlyVerifiedMaterial(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	c := checker{roots: f.roots, now: f.now}
	unrelated := makeFixture(t)
	for _, tt := range []struct {
		name, host string
		input      []*x509.Certificate
		count      int
	}{
		{"no alternate", "example.com", []*x509.Certificate{f.leaf, f.intermediate}, 0},
		{"hostname failure", "wrong.example", []*x509.Certificate{f.leaf, f.intermediate, f.cross}, 0},
		{"unrelated only", "example.com", []*x509.Certificate{f.leaf, f.intermediate, unrelated.intermediate}, 0},
		{"unrelated with alternate", "example.com", []*x509.Certificate{f.leaf, f.intermediate, f.cross, unrelated.intermediate}, 1},
		{"duplicate alternate", "example.com", []*x509.Certificate{f.leaf, f.intermediate, f.cross, f.cross}, 1},
		{"wrong wire order", "example.com", []*x509.Certificate{f.leaf, f.cross, f.intermediate}, 1},
		{"unordered PEM", "", []*x509.Certificate{f.cross, f.intermediate, f.leaf}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := c.check(context.Background(), tt.input, tt.host, false)
			if len(r.CompatibilityChains) != tt.count {
				t.Fatalf("%+v", r)
			}
			if !r.Verified && (r.PEM != "" || len(r.CompatibilityChains) > 0) {
				t.Fatal("unverified result exported a chain")
			}
			if tt.count > 0 {
				assertExportedPath(t, r.CompatibilityChains[0].PEM, []*x509.Certificate{f.leaf, f.intermediate, f.cross}, f.alternateRoot, c)
			}
		})
	}
	expired := c
	expired.now = f.leaf.NotAfter.Add(1)
	r := expired.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, f.cross}, "example.com", true)
	if r.Verified || r.PEM != "" || len(r.CompatibilityChains) > 0 {
		t.Fatal("expired chain exported")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = c.check(ctx, []*x509.Certificate{f.leaf, f.intermediate, f.cross}, "example.com", true)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"compatibilityChains":[]`) {
		t.Fatalf("empty JSON contract: %s", b)
	}
}

func TestCompatibilityExportDeterministicShortestPerAnchor(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	c := checker{roots: f.roots, now: f.now}
	ct := *f.intermediate
	ct.SerialNumber = big.NewInt(80)
	ct.AuthorityKeyId = nil
	shortA := issue(t, &ct, f.alternateRoot, f.intermediate.PublicKey, f.alternateKey)
	ct.SerialNumber = big.NewInt(81)
	shortB := issue(t, &ct, f.alternateRoot, f.intermediate.PublicKey, f.alternateKey)
	winner := shortA
	if digest(shortB) < digest(shortA) {
		winner = shortB
	}
	var reference []CompatibilityChain
	for _, extras := range [][]*x509.Certificate{{f.cross, shortA, shortB}, {shortB, f.cross, shortA}, {shortA, shortB, f.cross}} {
		input := append([]*x509.Certificate{f.leaf, f.intermediate}, extras...)
		r := c.check(context.Background(), input, "example.com", false)
		if !r.Verified || len(r.CompatibilityChains) != 1 {
			t.Fatalf("%+v", r)
		}
		assertExportedPath(t, r.CompatibilityChains[0].PEM, []*x509.Certificate{f.leaf, winner}, f.alternateRoot, c)
		if reference == nil {
			reference = r.CompatibilityChains
		} else if !reflect.DeepEqual(reference, r.CompatibilityChains) {
			t.Fatal("same-anchor export depends on input order")
		}
	}
}

func TestCompatibilityExportMultipleAnchorsStableOrder(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	c := checker{roots: f.roots, now: f.now}
	k := key(t)
	rt := *f.alternateRoot
	rt.SerialNumber = big.NewInt(90)
	rt.Subject = pkix.Name{CommonName: "Another Alternate Root"}
	rt.RawSubject = nil
	rt.PublicKey = nil
	root := issue(t, &rt, &rt, &k.PublicKey, k)
	ct := *f.root
	ct.SerialNumber = big.NewInt(91)
	ct.AuthorityKeyId = nil
	cross := issue(t, &ct, root, f.root.PublicKey, k)
	f.roots.AddCert(root)
	a := c.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, f.cross, cross}, "example.com", true)
	b := c.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, cross, f.cross}, "example.com", true)
	if len(a.CompatibilityChains) != 2 || !reflect.DeepEqual(a.CompatibilityChains, b.CompatibilityChains) {
		t.Fatal("alternate root enumeration unstable")
	}
	if a.CompatibilityChains[0].Root != caLabel(root) || a.CompatibilityChains[1].Root != caLabel(f.alternateRoot) {
		t.Fatalf("unexpected anchor labels: %+v", a.CompatibilityChains)
	}
	assertExportedPath(t, a.CompatibilityChains[0].PEM, []*x509.Certificate{f.leaf, f.intermediate, cross, root}, root, c)
	assertExportedPath(t, a.CompatibilityChains[1].PEM, []*x509.Certificate{f.leaf, f.intermediate, f.cross, f.alternateRoot}, f.alternateRoot, c)
}

func TestCompatibilityExportRequiresSubmittedCompatibilityCA(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	c := checker{roots: f.roots, now: f.now, fetch: func(context.Context, string) ([]byte, error) { return []byte(pemCerts(f.intermediate, f.cross)), nil }}
	r := c.check(context.Background(), []*x509.Certificate{f.leaf}, "example.com", false)
	if !r.Verified || len(r.CompatibilityChains) > 0 {
		t.Fatal("AIA-only cross-certificate was exported as a submitted compatibility option")
	}
	c.roots = x509.NewCertPool()
	r = c.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, f.cross, f.root, f.alternateRoot}, "example.com", true)
	if r.Verified || r.PEM != "" || len(r.CompatibilityChains) > 0 {
		t.Fatal("supplied untrusted roots exported a verified chain")
	}
}
