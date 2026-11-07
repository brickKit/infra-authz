package core

import (
	"fmt"
	"strings"
)

// Registry is who owns each resource type and permission key (the assembly project's registry, delivered as
// configuration): kind ("resource_type" or "permission") + "\x00" + key -> owner component; a retired permission key
// (an optional fourth column, its retirement date: protocol 19, a key is retired, never reused) also as
// "retired\x00" + key.
type Registry map[string]string

func ParseRegistry(tsv string) (Registry, error) {
	r := Registry{}
	for i, line := range strings.Split(tsv, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "kind\t") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 || (f[0] != "resource_type" && f[0] != "permission") {
			return nil, fmt.Errorf("AUTHZ_REGISTRY line %d: want kind, key, owner_component and, for a retired permission key, its retirement", i+1)
		}
		r[f[0]+"\x00"+f[1]] = f[2]
		if len(f) > 3 && strings.TrimSpace(f[3]) != "" && f[0] == "permission" {
			r["retired\x00"+f[1]] = f[3]
		}
	}
	return r, nil
}

func (r Registry) Owner(kind, key string) string { return r[kind+"\x00"+key] }

// Usable: a permission key registered and not retired (security 08: only those take part in an effective segment).
func (r Registry) Usable(key string) bool {
	return r.Owner("permission", key) != "" && r["retired\x00"+key] == ""
}

// registry parses AUTHZ_REGISTRY again only when it changed (the SDK re-reads the file).
func RegistryNow(m *Base) (Registry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.RegistryText(); t != m.regText || m.reg == nil {
		r, err := ParseRegistry(t)
		if err != nil {
			return nil, err
		}
		m.regText, m.reg = t, r
	}
	return m.reg, nil
}
