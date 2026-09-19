package domaincheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// rdapBootstrap is the IANA RDAP bootstrap document: services is a list of
// [tlds, baseURLs] pairs.
type rdapBootstrap struct {
	Services [][][]string `json:"services"`
}

// rdapDomain is the subset of an RDAP domain object used here.
type rdapDomain struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []struct {
		Roles      []string        `json:"roles"`
		VCardArray json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
	SecureDNS struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
}

// rdapRegistration resolves registration data through IANA's RDAP bootstrap.
// found=false means the registry has no RDAP record for the domain.
func (a *Analyzer) rdapRegistration(ctx context.Context, domain string) (Registration, bool, error) {
	base, err := a.rdapBase(ctx, tld(domain))
	if err != nil {
		return Registration{}, false, err
	}
	if base == "" {
		return Registration{}, false, nil
	}

	endpoint := strings.TrimRight(base, "/") + "/domain/" + url.PathEscape(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Registration{}, false, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return Registration{}, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Registration{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Registration{}, false, fmt.Errorf("rdap: %s returned %d", endpoint, resp.StatusCode)
	}

	var doc rdapDomain
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return Registration{}, false, fmt.Errorf("rdap: decode: %w", err)
	}

	reg := Registration{
		Found:  true,
		Source: "rdap",
		Domain: domain,
	}
	for _, event := range doc.Events {
		when, ok := parseTime(event.Date)
		if !ok {
			continue
		}
		switch strings.ToLower(event.Action) {
		case "registration":
			reg.CreatedAt = when
		case "expiration":
			reg.ExpiresAt = when
		case "last changed", "last update":
			reg.UpdatedAt = when
		}
	}
	reg.Statuses = dedupe(doc.Status)
	for _, ns := range doc.Nameservers {
		if name := strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")); name != "" {
			reg.Nameservers = append(reg.Nameservers, name)
		}
	}
	if doc.SecureDNS.DelegationSigned {
		reg.DNSSEC = "signed"
	} else {
		reg.DNSSEC = "unsigned"
	}
	for _, entity := range doc.Entities {
		for _, role := range entity.Roles {
			switch strings.ToLower(role) {
			case "registrar":
				if reg.Registrar == "" {
					reg.Registrar = vcardField(entity.VCardArray, "fn")
				}
			case "registrant":
				if reg.Registrant == "" {
					reg.Registrant = vcardField(entity.VCardArray, "fn")
				}
				if reg.Country == "" {
					reg.Country = vcardField(entity.VCardArray, "country")
				}
			}
		}
	}
	return reg, true, nil
}

// rdapBase fetches (and caches) the IANA RDAP bootstrap and returns the base
// URL for a TLD, or "" when the TLD has no RDAP service.
func (a *Analyzer) rdapBase(ctx context.Context, tld string) (string, error) {
	a.mu.Lock()
	if a.bootstrapDone {
		base := a.bootstrap[strings.ToLower(tld)]
		err := a.bootstrapErr
		a.mu.Unlock()
		return base, err
	}
	a.mu.Unlock()

	index, err := a.fetchBootstrap(ctx)

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bootstrapDone {
		// Another goroutine won the race; use its result.
		return a.bootstrap[strings.ToLower(tld)], a.bootstrapErr
	}
	a.bootstrap = index
	a.bootstrapErr = err
	a.bootstrapDone = true
	return index[strings.ToLower(tld)], err
}

func (a *Analyzer) fetchBootstrap(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.bootstrapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap bootstrap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap bootstrap: status %d", resp.StatusCode)
	}

	var doc rdapBootstrap
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("rdap bootstrap: decode: %w", err)
	}
	index := make(map[string]string)
	for _, service := range doc.Services {
		if len(service) < 2 || len(service[1]) == 0 {
			continue
		}
		base := service[1][0]
		for _, name := range service[0] {
			index[strings.ToLower(name)] = base
		}
	}
	return index, nil
}

// vcardField extracts a property value from an RDAP vcardArray, which is
// ["vcard", [ ["fn", {}, "text", "Acme"], ... ]].
func vcardField(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var outer []json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer) < 2 {
		return ""
	}
	var properties []json.RawMessage
	if err := json.Unmarshal(outer[1], &properties); err != nil {
		return ""
	}
	for _, property := range properties {
		var fields []json.RawMessage
		if err := json.Unmarshal(property, &fields); err != nil || len(fields) < 4 {
			continue
		}
		var name string
		if err := json.Unmarshal(fields[0], &name); err != nil || !strings.EqualFold(name, key) {
			continue
		}
		var value string
		if err := json.Unmarshal(fields[3], &value); err == nil {
			return value
		}
		// Some properties (e.g. adr) carry an array of components.
		var parts []string
		if err := json.Unmarshal(fields[3], &parts); err == nil {
			var nonEmpty []string
			for _, part := range parts {
				if strings.TrimSpace(part) != "" {
					nonEmpty = append(nonEmpty, part)
				}
			}
			return strings.Join(nonEmpty, ", ")
		}
	}
	return ""
}

// parseTime accepts the timestamp layouts seen across RDAP servers.
func parseTime(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	layouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UnixMilli(), true
		}
	}
	return 0, false
}

// dedupe returns the non-empty values with duplicates and surrounding space
// removed, preserving order.
func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
