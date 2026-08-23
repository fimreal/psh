package main

import (
	"os"
	"path/filepath"
	"testing"

	tlspkg "github.com/fimreal/psh/pkg/tls"
)

func TestLoadMCPAPIKeys_Literals(t *testing.T) {
	keys := loadMCPAPIKeys("token-a, token-b ,,token-c")

	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys["token-a"] != "mcp-key-1" || keys["token-b"] != "mcp-key-2" || keys["token-c"] != "mcp-key-3" {
		t.Errorf("unexpected identifiers: %v", keys)
	}
}

func TestLoadMCPAPIKeys_Empty(t *testing.T) {
	if keys := loadMCPAPIKeys(""); len(keys) != 0 {
		t.Fatalf("expected no keys, got %v", keys)
	}
	if keys := loadMCPAPIKeys(" , ,"); len(keys) != 0 {
		t.Fatalf("expected no keys, got %v", keys)
	}
}

func TestLoadMCPAPIKeys_KeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.txt")
	content := "# comment line\ntoken-from-file\n\n   \nanother-token\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	keys := loadMCPAPIKeys(path + ",literal-token")

	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d: %v", len(keys), keys)
	}
	for _, tok := range []string{"token-from-file", "another-token", "literal-token"} {
		if _, ok := keys[tok]; !ok {
			t.Errorf("missing key %q", tok)
		}
	}
}

func TestLoadMCPAPIKeys_DuplicateTokensKeepFirstIdentifier(t *testing.T) {
	keys := loadMCPAPIKeys("dup,other,dup")

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys["dup"] != "mcp-key-1" {
		t.Errorf("duplicate token identifier = %q, want mcp-key-1", keys["dup"])
	}
	if keys["other"] != "mcp-key-2" {
		t.Errorf("identifier sequence broken: %v", keys)
	}
}

func TestBuildTLSConfig_None(t *testing.T) {
	cfg, err := buildTLSConfig("", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil TLS config without certs or auto-certs")
	}
}

func TestBuildTLSConfig_PartialCertErrors(t *testing.T) {
	if _, err := buildTLSConfig("cert.pem", "", false); err == nil {
		t.Fatal("expected error when only the certificate path is set")
	}
	if _, err := buildTLSConfig("", "key.pem", false); err == nil {
		t.Fatal("expected error when only the key path is set")
	}
}

func TestBuildTLSConfig_MissingCertFileErrors(t *testing.T) {
	if _, err := buildTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem", false); err == nil {
		t.Fatal("expected error for missing cert files")
	}
}

func TestBuildTLSConfig_AutoCerts(t *testing.T) {
	cfg, err := buildTLSConfig("", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatal("expected self-signed certificate with auto-certs")
	}
}

func TestBuildTLSConfig_ExplicitCertKey(t *testing.T) {
	cert, err := tlspkg.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := buildTLSConfig(certPath, keyPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatal("expected certificate from explicit paths")
	}
}
