package chain

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

type crossFixture struct {
	fixture
	alternateRoot, cross *x509.Certificate
}

func makeCrossFixture(t *testing.T, alterRoot, alterCross func(*x509.Certificate)) crossFixture {
	t.Helper()
	f := makeFixture(t)
	k := key(t)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(40), Subject: pkix.Name{CommonName: "Example Trust", OrganizationalUnit: []string{"Example Trust Root CA - R3"}}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 4}
	if alterRoot != nil {
		alterRoot(rootTemplate)
	}
	root := issue(t, rootTemplate, rootTemplate, &k.PublicKey, k)
	crossTemplate := *f.root
	crossTemplate.SerialNumber = big.NewInt(41)
	crossTemplate.AuthorityKeyId = nil
	if alterCross != nil {
		alterCross(&crossTemplate)
	}
	cross := issue(t, &crossTemplate, root, f.root.PublicKey, k)
	f.roots.AddCert(root)
	return crossFixture{f, root, cross}
}

func issueByCode(t *testing.T, r Result, code string) Issue {
	t.Helper()
	for _, i := range r.Issues {
		if i.Code == code {
			return i
		}
	}
	t.Fatalf("missing issue %s: %+v", code, r.Issues)
	return Issue{}
}

func TestCrossSignedAlternateAnchorInformational(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	c := checker{roots: f.roots, now: f.now}
	input := []*x509.Certificate{f.leaf, f.intermediate, f.cross}
	for _, includeRoot := range []bool{false, true} {
		r := c.check(context.Background(), input, "example.com", includeRoot)
		if r.Status != "ok" || !r.Verified || !r.Complete || hasIssue(r, "extra_certificates") {
			t.Fatalf("%+v", r)
		}
		info := issueByCode(t, r, "alternate_trust_path")
		if info.Severity != "info" || !strings.Contains(info.Message, "Example Trust Root CA - R3") || !strings.Contains(info.Message, "Скачиваемый PEM") {
			t.Fatalf("%+v", info)
		}
		baseline := c.check(context.Background(), input[:2], "example.com", includeRoot)
		if r.PEM != baseline.PEM {
			t.Fatal("alternate path changed downloadable PEM")
		}
		for i, p := range r.Presented {
			if p.SHA256 != digest(input[i]) {
				t.Fatal("presented order changed")
			}
		}
	}
}

func TestCrossSignedIntermediateAlternateAnchor(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	// An alternate root can cross-sign a preferred intermediate as well as a root.
	// Use a new root with a retained key to create this independent verified path.
	k := key(t)
	rt := *f.alternateRoot
	rt.SerialNumber = big.NewInt(50)
	rt.PublicKey = nil
	root := issue(t, &rt, &rt, &k.PublicKey, k)
	ct := *f.intermediate
	ct.SerialNumber = big.NewInt(51)
	ct.AuthorityKeyId = nil
	cross := issue(t, &ct, root, f.intermediate.PublicKey, k)
	f.roots.AddCert(root)
	r := (&checker{roots: f.roots, now: f.now}).check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, cross}, "example.com", false)
	if r.Status != "ok" || !r.Verified || !hasIssue(r, "alternate_trust_path") {
		t.Fatalf("%+v", r)
	}
}

func TestCrossSignedExtrasDoNotHideWarningsAndErrors(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	other := makeFixture(t)
	for _, tt := range []struct {
		name               string
		input              []*x509.Certificate
		host, code, status string
		info               bool
	}{
		{"duplicate", []*x509.Certificate{f.leaf, f.intermediate, f.cross, f.cross}, "example.com", "duplicate_certificates", "warning", true},
		{"unrelated", []*x509.Certificate{f.leaf, f.intermediate, f.cross, other.intermediate}, "example.com", "extra_certificates", "warning", true},
		{"self-signed root", []*x509.Certificate{f.leaf, f.intermediate, f.cross, f.alternateRoot}, "example.com", "unnecessary_root", "warning", true},
		{"preferred root included", []*x509.Certificate{f.leaf, f.intermediate, f.root, f.cross}, "example.com", "unnecessary_root", "warning", true},
		{"alternate wire order", []*x509.Certificate{f.leaf, f.cross, f.intermediate}, "example.com", "incorrect_order", "warning", true},
		{"preferred wire order", []*x509.Certificate{f.intermediate, f.leaf, f.cross}, "", "incorrect_order", "warning", true},
		{"hostname", []*x509.Certificate{f.leaf, f.intermediate, f.cross}, "wrong.example", "hostname_mismatch", "error", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := (&checker{roots: f.roots, now: f.now}).check(context.Background(), tt.input, tt.host, false)
			if r.Status != tt.status || !hasIssue(r, tt.code) || hasIssue(r, "alternate_trust_path") != tt.info {
				t.Fatalf("%+v", r)
			}
			if tt.status == "error" && (r.Verified || r.PEM != "") {
				t.Fatal("error produced verified PEM")
			}
			if tt.status == "error" && strings.Contains(issueByCode(t, r, "alternate_trust_path").Message, "Скачиваемый PEM") {
				t.Fatal("error advertises a downloadable PEM")
			}
			if tt.name == "duplicate" && strings.Count(issueByCode(t, r, "alternate_trust_path").Message, "Дополнительный сертификат") != 1 {
				t.Fatal("duplicate info prose")
			}
		})
	}
}

func TestInvalidCrossSignedCertificatesRemainExtra(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		root, cross             func(*x509.Certificate)
		untrust, breakSignature bool
	}{
		{name: "untrusted anchor", untrust: true},
		{name: "expired anchor", root: func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(-time.Hour) }},
		{name: "expired cross-certificate", cross: func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(-time.Hour) }},
		{name: "future cross-certificate", cross: func(c *x509.Certificate) { c.NotBefore = c.NotAfter.Add(time.Hour) }},
		{name: "wrong EKU", cross: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "not a CA", cross: func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = -1; c.MaxPathLenZero = false }},
		{name: "invalid signature", breakSignature: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := makeCrossFixture(t, tt.root, tt.cross)
			if tt.untrust {
				f.roots = x509.NewCertPool()
				f.roots.AddCert(f.root)
			}
			if tt.breakSignature {
				der := append([]byte(nil), f.cross.Raw...)
				der[len(der)-1] ^= 1
				var err error
				f.cross, err = x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
			}
			r := (&checker{roots: f.roots, now: f.now}).check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, f.cross}, "example.com", false)
			if r.Status != "warning" || !r.Verified || !hasIssue(r, "extra_certificates") || hasIssue(r, "alternate_trust_path") {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestAlternateSameAnchorRemainsExtra(t *testing.T) {
	f := makeFixture(t)
	bk := key(t)
	bt := *f.root
	bt.SerialNumber = big.NewInt(60)
	bt.Subject = pkix.Name{CommonName: "Bridge CA"}
	bt.RawSubject = nil
	bt.AuthorityKeyId = nil
	bridge := issue(t, &bt, f.root, &bk.PublicKey, f.rootKey)
	ct := *f.intermediate
	ct.SerialNumber = big.NewInt(61)
	ct.AuthorityKeyId = nil
	cross := issue(t, &ct, bridge, f.intermediate.PublicKey, bk)
	c := checker{roots: f.roots, now: f.now}
	input := []*x509.Certificate{f.leaf, f.intermediate, cross, bridge}
	paths, err := c.verify(f.leaf, input)
	if err != nil || len(paths) < 2 {
		t.Fatalf("fixture must provide two valid paths: %d %v", len(paths), err)
	}
	r := c.check(context.Background(), input, "example.com", false)
	if r.Status != "warning" || !hasIssue(r, "extra_certificates") || hasIssue(r, "alternate_trust_path") {
		t.Fatalf("%+v", r)
	}
}

func TestCrossSignedWithMissingIntermediateStaysWarning(t *testing.T) {
	f := makeCrossFixture(t, nil, nil)
	c := checker{roots: f.roots, now: f.now, fetch: func(context.Context, string) ([]byte, error) { return f.intermediate.Raw, nil }}
	r := c.check(context.Background(), []*x509.Certificate{f.leaf, f.cross}, "example.com", false)
	if r.Status != "warning" || !r.Verified || r.Complete || !hasIssue(r, "missing_intermediate") || !hasIssue(r, "alternate_trust_path") {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(issueByCode(t, r, "alternate_trust_path").Message, "позволяет клиентам") {
		t.Fatal("incomplete supplied path claimed complete")
	}
}

func TestAlternatePathWithAdditionalIntermediate(t *testing.T) {
	f := makeFixture(t)
	rk, bk := key(t), key(t)
	rt := *f.root
	rt.SerialNumber = big.NewInt(70)
	rt.Subject = pkix.Name{CommonName: "Alternate Root"}
	rt.RawSubject = nil
	rt.AuthorityKeyId = nil
	rt.PublicKey = nil
	rt.MaxPathLen = 4
	root := issue(t, &rt, &rt, &rk.PublicKey, rk)
	bt := rt
	bt.SerialNumber = big.NewInt(71)
	bt.Subject = pkix.Name{CommonName: "Alternate Bridge CA"}
	bt.RawSubject = nil
	bt.MaxPathLen = 2
	bridge := issue(t, &bt, root, &bk.PublicKey, rk)
	ct := *f.root
	ct.SerialNumber = big.NewInt(72)
	ct.AuthorityKeyId = nil
	cross := issue(t, &ct, bridge, f.root.PublicKey, bk)
	f.roots.AddCert(root)
	c := checker{roots: f.roots, now: f.now}
	r := c.check(context.Background(), []*x509.Certificate{f.leaf, f.intermediate, cross, bridge}, "example.com", false)
	if r.Status != "ok" || !r.Verified || !r.Complete || hasIssue(r, "extra_certificates") {
		t.Fatalf("%+v", r)
	}
	info := issueByCode(t, r, "alternate_trust_path")
	if !strings.Contains(info.Message, "Alternate Bridge CA") || !strings.Contains(info.Message, "Alternate Root") {
		t.Fatalf("%+v", info)
	}
}
