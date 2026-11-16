// Package chain inspects the exact certificate list supplied by a TLS peer and
// rebuilds a chain using the operating system trust store and bounded AIA lookups.
package chain

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Certificate struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"notAfter"`
	SHA256   string `json:"sha256"`
}

type Issue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Result struct {
	Status    string        `json:"status"`
	Message   string        `json:"message"`
	Presented []Certificate `json:"presented"`
	Chain     []Certificate `json:"chain"`
	PEM       string        `json:"pem"`
	Issues    []Issue       `json:"issues"`
	Verified  bool          `json:"verified"`
	Complete  bool          `json:"complete"`
	Host      string        `json:"host,omitempty"`
}

type checker struct {
	roots *x509.CertPool
	now   time.Time
	fetch func(context.Context, string) ([]byte, error)
}

// Check accepts exactly one of host (DNS name/IP, optionally :port) and certPEM.
// It never treats an uploaded or downloaded root as a trusted root. PEM is
// returned only for a successfully verified path (and hostname for live checks).
func Check(ctx context.Context, host, certPEM string, includeRoot bool) (Result, error) {
	if (strings.TrimSpace(host) == "") == (strings.TrimSpace(certPEM) == "") {
		return Result{}, errors.New("укажите хост или PEM, только одно поле")
	}
	if len(certPEM) > maxBody {
		return Result{}, errors.New("PEM превышает 2 МиБ")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	guard, err := newNetworkGuard()
	if err != nil {
		return Result{}, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return Result{}, errors.New("не удалось загрузить системное хранилище доверенных сертификатов")
	}
	client := guard.httpClient()
	defer client.CloseIdleConnections()
	c := checker{roots: roots, now: time.Now(), fetch: func(ctx context.Context, u string) ([]byte, error) { return fetchAIA(ctx, client, u) }}
	var certs []*x509.Certificate
	name := ""
	if strings.TrimSpace(host) != "" {
		var port string
		name, port, err = parseHost(host)
		if err != nil {
			return Result{}, err
		}
		certs, err = guard.certificates(ctx, name, port)
		if err != nil {
			return Result{}, err
		}
	} else {
		certs, err = parsePEM([]byte(certPEM))
		if err != nil {
			return Result{}, err
		}
	}
	if err := validateCertificateSizes(certs); err != nil {
		return Result{}, err
	}
	return c.check(ctx, certs, name, includeRoot), nil
}

func validateCertificateSizes(cs []*x509.Certificate) error {
	if len(cs) > 32 {
		return errors.New("допускается не более 32 сертификатов")
	}
	for _, c := range cs {
		if len(c.Raw) > 256<<10 {
			return errors.New("сертификат слишком велик")
		}
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && (pub.N.BitLen() > 8192 || pub.E > 2147483647) {
			return errors.New("RSA-ключ превышает ограничение вычислительных ресурсов")
		}
	}
	return nil
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, errors.New("PEM содержит посторонние данные")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("ожидаются только PEM-блоки CERTIFICATE")
		}
		if len(block.Bytes) > 256<<10 {
			return nil, errors.New("сертификат слишком велик")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("некорректный сертификат PEM")
		}
		certs = append(certs, cert)
		if len(certs) > 32 {
			return nil, errors.New("допускается не более 32 сертификатов")
		}
		data = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("PEM не содержит сертификатов")
	}
	return certs, nil
}

func digest(c *x509.Certificate) string { d := sha256.Sum256(c.Raw); return hex.EncodeToString(d[:]) }
func describe(c *x509.Certificate) Certificate {
	return Certificate{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotAfter: c.NotAfter.UTC().Format(time.RFC3339), SHA256: digest(c)}
}
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
func parentOf(parent, child *x509.Certificate) bool {
	return bytes.Equal(child.RawIssuer, parent.RawSubject) && child.CheckSignatureFrom(parent) == nil
}

func (c *checker) verify(leaf *x509.Certificate, candidates []*x509.Certificate) ([][]*x509.Certificate, error) {
	pool := x509.NewCertPool()
	for _, cert := range candidates {
		if !bytes.Equal(cert.Raw, leaf.Raw) {
			pool.AddCert(cert)
		}
	}
	return leaf.Verify(x509.VerifyOptions{Roots: c.roots, Intermediates: pool, CurrentTime: c.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
}

func needsIssuer(err error) bool {
	var unknown x509.UnknownAuthorityError
	return errors.As(err, &unknown)
}

// sameCAIdentity identifies reissued/cross-signed versions of one CA, not merely
// certificates with a matching name. It is only a filter; a complete verified
// leaf-to-system-root path is still required before an extra is informational.
func sameCAIdentity(a, b *x509.Certificate) bool {
	return a.IsCA && b.IsCA && bytes.Equal(a.RawSubject, b.RawSubject) && bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo)
}

func pathContains(path []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range path {
		if bytes.Equal(c.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

// alternativePaths accepts extra members of another fully verified path for
// this leaf, with a cross-signed version of a preferred CA and a distinct trust
// anchor. Matching signatures or CA identity alone never establish system trust.
func alternativePaths(cert *x509.Certificate, selected []*x509.Certificate, paths [][]*x509.Certificate) [][]*x509.Certificate {
	if selfSigned(cert) || !cert.IsCA {
		return nil
	}
	anchor := selected[len(selected)-1]
	var alternatives [][]*x509.Certificate
	for _, path := range paths {
		if len(path) < 2 || !bytes.Equal(path[0].Raw, selected[0].Raw) || !pathContains(path[:len(path)-1], cert) {
			continue
		}
		otherAnchor := path[len(path)-1]
		if bytes.Equal(otherAnchor.Raw, anchor.Raw) || sameCAIdentity(otherAnchor, anchor) {
			continue
		}
		crossSigned := false
		for _, member := range path[1 : len(path)-1] {
			for _, preferred := range selected[1:] {
				if !bytes.Equal(member.Raw, preferred.Raw) && sameCAIdentity(member, preferred) {
					crossSigned = true
					break
				}
			}
			if crossSigned {
				break
			}
		}
		if !crossSigned {
			continue
		}
		alternatives = append(alternatives, path)
	}
	return alternatives
}

func pathPresent(path []*x509.Certificate, indices map[string]int) bool {
	for _, cert := range path[:len(path)-1] {
		if _, ok := indices[digest(cert)]; !ok {
			return false
		}
	}
	return true
}

func pathInPresentedOrder(path []*x509.Certificate, indices map[string]int) bool {
	last := -1
	for _, cert := range path {
		if index, ok := indices[digest(cert)]; ok {
			if index < last {
				return false
			}
			last = index
		}
	}
	return true
}

func caLabel(cert *x509.Certificate) string {
	name := strings.TrimSpace(cert.Subject.CommonName)
	ous := strings.Join(cert.Subject.OrganizationalUnit, ", ")
	if name == "" {
		if ous != "" {
			return ous
		}
		return cert.Subject.String()
	}
	// Some roots use a generic CN, e.g. GlobalSign; their OU contains the
	// identifying generation, e.g. GlobalSign Root CA - R3.
	if strings.HasPrefix(strings.ToLower(ous), strings.ToLower(name)+" ") {
		return ous
	}
	if ous != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(ous)) {
		name += " (" + ous + ")"
	}
	return name
}

func (c *checker) check(ctx context.Context, original []*x509.Certificate, host string, includeRoot bool) Result {
	r := Result{Status: "ok", Presented: []Certificate{}, Chain: []Certificate{}, Issues: []Issue{}, Host: host}
	add := func(code, severity, message string) {
		for _, i := range r.Issues {
			if i.Code == code {
				return
			}
		}
		r.Issues = append(r.Issues, Issue{code, severity, message})
		if severity == "error" {
			r.Status = "error"
		} else if severity == "warning" && r.Status == "ok" {
			r.Status = "warning"
		}
	}
	if ctx.Err() != nil {
		add("canceled", "error", "Время проверки истекло или запрос отменён.")
		r.Message = "Проверка прервана."
		return r
	}
	if len(original) == 0 {
		add("empty_chain", "error", "Сертификаты отсутствуют.")
		r.Message = "Сертификаты отсутствуют."
		return r
	}
	seen := make(map[string]bool)
	var candidates []*x509.Certificate
	for _, cert := range original {
		r.Presented = append(r.Presented, describe(cert))
		if selfSigned(cert) {
			add("unnecessary_root", "warning", "Исходная цепочка содержит корневой сертификат; обычно серверу не нужно его отправлять.")
		}
		id := digest(cert)
		if seen[id] {
			add("duplicate_certificates", "warning", "В исходной цепочке есть повторяющиеся сертификаты.")
		} else {
			candidates = append(candidates, cert)
			seen[id] = true
		}
	}
	leaf := original[0]
	if host == "" {
		var leaves []*x509.Certificate
		for _, cert := range candidates {
			if !cert.IsCA {
				leaves = append(leaves, cert)
			}
		}
		if len(leaves) == 0 {
			for _, cert := range candidates {
				isParent := false
				for _, child := range candidates {
					if !bytes.Equal(child.Raw, cert.Raw) && parentOf(cert, child) {
						isParent = true
						break
					}
				}
				if !isParent {
					leaves = append(leaves, cert)
				}
			}
		}
		if len(leaves) > 0 {
			leaf = leaves[0]
		}
		if len(leaves) > 1 {
			add("ambiguous_leaf", "error", "В PEM несколько независимых конечных сертификатов; загрузите одну цепочку.")
		}
	}
	if host != "" {
		if err := leaf.VerifyHostname(host); err != nil {
			add("hostname_mismatch", "error", "Сертификат не соответствует имени хоста.")
		}
	}
	paths, verifyErr := c.verify(leaf, candidates)
	// Only certificates reachable by a valid issuer signature may trigger more AIA requests.
	attempted := make(map[string]bool)
	fetches := 0
	for round := 0; needsIssuer(verifyErr) && round < 8 && c.fetch != nil && len(candidates) < 32; round++ {
		if ctx.Err() != nil {
			break
		}
		reachable := map[string]bool{digest(leaf): true}
		queue := []*x509.Certificate{leaf}
		for len(queue) > 0 {
			if ctx.Err() != nil {
				break
			}
			child := queue[0]
			queue = queue[1:]
			for _, parent := range candidates {
				id := digest(parent)
				if !reachable[id] && parentOf(parent, child) {
					reachable[id] = true
					queue = append(queue, parent)
				}
			}
		}
		added := false
		for _, cert := range append([]*x509.Certificate(nil), candidates...) {
			if !reachable[digest(cert)] || selfSigned(cert) {
				continue
			}
			for j, u := range cert.IssuingCertificateURL {
				if j >= 3 || fetches >= 10 || ctx.Err() != nil {
					break
				}
				if attempted[u] {
					continue
				}
				attempted[u] = true
				fetches++
				data, err := c.fetch(ctx, u)
				if err != nil {
					continue
				}
				parsed, err := parseIssuerData(data)
				if err != nil {
					continue
				}
				if validateCertificateSizes(parsed) != nil {
					continue
				}
				for _, p := range parsed {
					id := digest(p)
					if !seen[id] && p.IsCA && len(candidates) < 32 {
						candidates = append(candidates, p)
						seen[id] = true
						added = true
					}
				}
			}
		}
		if ctx.Err() != nil {
			break
		}
		paths, verifyErr = c.verify(leaf, candidates)
		if !added {
			break
		}
	}
	var selected []*x509.Certificate
	if verifyErr == nil && len(paths) > 0 {
		selected = paths[0]
		for _, p := range paths {
			if len(p) < len(selected) {
				selected = p
			}
		}
		r.Complete = true
		inOriginal := make(map[string]int)
		for i, cert := range original {
			if _, ok := inOriginal[digest(cert)]; !ok {
				inOriginal[digest(cert)] = i
			}
		}
		used := make(map[string]bool)
		lastIndex := -1
		for i, cert := range selected {
			id := digest(cert)
			used[id] = true
			index, present := inOriginal[id]
			isRoot := i == len(selected)-1 && i > 0
			if !present && !isRoot {
				r.Complete = false
				add("missing_intermediate", "warning", "В исходной цепочке отсутствует промежуточный сертификат; он загружен по AIA.")
			}
			if present {
				if index < lastIndex {
					add("incorrect_order", "warning", "Сертификаты в исходной цепочке расположены в неверном порядке.")
				}
				lastIndex = index
			}
		}
		var alternateMessages []string
		explained := make(map[string]bool)
		for _, cert := range original {
			if selfSigned(cert) {
				add("unnecessary_root", "warning", "Исходная цепочка содержит корневой сертификат; обычно серверу не нужно его отправлять.")
			}
			if !used[digest(cert)] {
				if alternatives := alternativePaths(cert, selected, paths); len(alternatives) > 0 {
					path := alternatives[0]
					for _, p := range alternatives {
						if pathPresent(p, inOriginal) && pathInPresentedOrder(p, inOriginal) {
							path = p
							break
						}
					}
					// Also check the compatibility path's wire order: selected-only
					// checks miss leaf,cross-certificate,issuing-CA permutations.
					ordered := pathInPresentedOrder(path, inOriginal)
					if !ordered {
						add("incorrect_order", "warning", "Сертификаты в исходной цепочке расположены в неверном порядке.")
					}
					if !pathPresent(path, inOriginal) {
						r.Complete = false
						add("missing_intermediate", "warning", "В исходной цепочке отсутствует промежуточный сертификат; он загружен по AIA.")
					}
					if !explained[digest(cert)] {
						message := fmt.Sprintf("Дополнительный сертификат «%s» позволяет клиентам, которые доверяют корню «%s», проверить эту же цепочку.", caLabel(cert), caLabel(path[len(path)-1]))
						if !ordered || !pathPresent(path, inOriginal) {
							message = fmt.Sprintf("Для дополнительного сертификата «%s» проверен альтернативный путь к корню «%s». Замечания к составу и порядку цепочки указаны отдельно.", caLabel(cert), caLabel(path[len(path)-1]))
						}
						alternateMessages = append(alternateMessages, message)
						explained[digest(cert)] = true
					}
				} else {
					add("extra_certificates", "warning", "В исходной цепочке есть сертификаты вне выбранного доверенного пути.")
				}
			}
		}
		if len(alternateMessages) > 0 {
			message := strings.Join(alternateMessages, " ")
			if r.Status != "error" {
				message += " Скачиваемый PEM содержит только выбранный путь доверия. Старым клиентам может требоваться альтернативный путь."
			}
			add("alternate_trust_path", "info", message)
		}
	} else {
		var unknown x509.UnknownAuthorityError
		if errors.As(verifyErr, &unknown) {
			add("untrusted_chain", "error", "Не удалось построить цепочку до доверенного системного корня. Возможен недостающий промежуточный сертификат или частный УЦ.")
		} else {
			add("invalid_chain", "error", "Проверка цепочки не пройдена: "+verifyErr.Error())
		}
		selected = diagnosticPath(leaf, candidates)
		lastIndex := -1
		for _, cert := range selected {
			for index, originalCert := range original {
				if bytes.Equal(cert.Raw, originalCert.Raw) {
					if index < lastIndex {
						add("incorrect_order", "warning", "Сертификаты в исходной цепочке расположены в неверном порядке.")
					}
					lastIndex = index
					break
				}
			}
		}
		last := selected[len(selected)-1]
		if !selfSigned(last) {
			add("missing_issuer", "error", "Не найден доверенный издатель последнего доступного сертификата. Проверьте промежуточные сертификаты и доступность AIA.")
		}
	}
	for _, cert := range selected {
		r.Chain = append(r.Chain, describe(cert))
		if c.now.Before(cert.NotBefore) {
			add("not_yet_valid", "error", "Один из сертификатов цепочки ещё не вступил в силу.")
		}
		if c.now.After(cert.NotAfter) {
			add("expired", "error", "Срок действия одного из сертификатов цепочки истёк.")
		}
	}
	r.Verified = verifyErr == nil && r.Status != "error"
	if r.Verified {
		out := selected
		if !includeRoot && len(out) > 1 {
			out = out[:len(out)-1]
		}
		var b strings.Builder
		for _, cert := range out {
			_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		}
		r.PEM = b.String()
	}
	switch r.Status {
	case "ok":
		r.Message = "Цепочка корректна и проверена по системному хранилищу доверия."
	case "warning":
		r.Message = "Доверенная цепочка построена; исходная цепочка требует исправления."
	default:
		r.Message = "Цепочка не прошла проверку. Подробности приведены ниже."
	}
	return r
}

func diagnosticPath(leaf *x509.Certificate, candidates []*x509.Certificate) []*x509.Certificate {
	out := []*x509.Certificate{leaf}
	seen := map[string]bool{digest(leaf): true}
	for len(out) < 16 {
		last := out[len(out)-1]
		if selfSigned(last) {
			break
		}
		var parent *x509.Certificate
		for _, c := range candidates {
			if !seen[digest(c)] && parentOf(c, last) {
				parent = c
				break
			}
		}
		if parent == nil {
			break
		}
		out = append(out, parent)
		seen[digest(parent)] = true
	}
	return out
}

// parseIssuerData supports raw DER certificates, PEM certificates, and the
// certificate set of a degenerate PKCS#7 SignedData (DER or PEM).
func parseIssuerData(data []byte) ([]*x509.Certificate, error) {
	if len(data) > maxBody {
		return nil, errors.New("ответ AIA слишком велик")
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		if block, rest := pem.Decode(data); block != nil && (block.Type == "PKCS7" || block.Type == "CMS") && len(bytes.TrimSpace(rest)) == 0 {
			return parsePKCS7(block.Bytes)
		}
		return parsePEM(data)
	}
	if cs, err := x509.ParseCertificates(data); err == nil && len(cs) > 0 && len(cs) <= 32 {
		return cs, nil
	}
	return parsePKCS7(data)
}

func rawElements(data []byte) ([]asn1.RawValue, error) {
	var values []asn1.RawValue
	for len(data) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(data, &v)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
		data = rest
		if len(values) > 64 {
			return nil, errors.New("слишком много элементов ASN.1")
		}
	}
	return values, nil
}

func parsePKCS7(data []byte) ([]*x509.Certificate, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) != 0 || outer.Tag != asn1.TagSequence || outer.Class != 0 {
		return nil, errors.New("некорректный PKCS#7")
	}
	parts, err := rawElements(outer.Bytes)
	if err != nil || len(parts) != 2 {
		return nil, errors.New("некорректный PKCS#7 ContentInfo")
	}
	var oid asn1.ObjectIdentifier
	if _, err = asn1.Unmarshal(parts[0].FullBytes, &oid); err != nil || !oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) || parts[1].Class != 2 || parts[1].Tag != 0 {
		return nil, errors.New("ожидается PKCS#7 SignedData")
	}
	var signed asn1.RawValue
	rest, err = asn1.Unmarshal(parts[1].Bytes, &signed)
	if err != nil || len(rest) != 0 || signed.Tag != asn1.TagSequence {
		return nil, errors.New("некорректный SignedData")
	}
	fields, err := rawElements(signed.Bytes)
	if err != nil || len(fields) < 4 {
		return nil, errors.New("неполный SignedData")
	}
	for _, field := range fields[3:] {
		if field.Class == 2 && field.Tag == 0 {
			items, err := rawElements(field.Bytes)
			if err != nil {
				return nil, err
			}
			var cs []*x509.Certificate
			for _, item := range items {
				if item.Class == 0 && item.Tag == asn1.TagSequence {
					cert, err := x509.ParseCertificate(item.FullBytes)
					if err != nil {
						return nil, fmt.Errorf("некорректный сертификат PKCS#7: %w", err)
					}
					cs = append(cs, cert)
					if len(cs) > 32 {
						return nil, errors.New("слишком много сертификатов PKCS#7")
					}
				}
			}
			if len(cs) > 0 {
				return cs, nil
			}
		}
	}
	return nil, errors.New("PKCS#7 не содержит сертификатов")
}
