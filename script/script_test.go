package script

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMetadata(t *testing.T) {
	// Test script with metadata
	scriptContent := `#!/bin/bash
#@ naGINI: 0.0.1
#@ Author: mrw <user@domain.tld>
#@ Template-Version: 0.0.1
#@ Info: Base Arch Install + Virtio Tools + XFCE4 + TigerVNC + Firefox + VLC + Veracrypt + ClamAV

echo "Installing Arch Linux..."
# Rest of the script...
`

	metadata := ParseMetadata([]byte(scriptContent))

	// Test that all metadata fields are correctly parsed
	if metadata.NaGINIVersion != "0.0.1" {
		t.Errorf("Expected NaGINIVersion '0.0.1', got '%s'", metadata.NaGINIVersion)
	}

	if metadata.Author != "mrw <user@domain.tld>" {
		t.Errorf("Expected Author 'mrw <user@domain.tld>', got '%s'", metadata.Author)
	}

	if metadata.TemplateVersion != "0.0.1" {
		t.Errorf("Expected TemplateVersion '0.0.1', got '%s'", metadata.TemplateVersion)
	}

	expectedInfo := "Base Arch Install + Virtio Tools + XFCE4 + TigerVNC + Firefox + VLC + Veracrypt + ClamAV"
	if metadata.Info != expectedInfo {
		t.Errorf("Expected Info '%s', got '%s'", expectedInfo, metadata.Info)
	}
}

func TestParseMetadataEmpty(t *testing.T) {
	// Test script without metadata
	scriptContent := `#!/bin/bash
echo "Installing Arch Linux..."
# Regular script without metadata
`

	metadata := ParseMetadata([]byte(scriptContent))

	// All fields should be empty
	if metadata.NaGINIVersion != "" {
		t.Errorf("Expected empty NaGINIVersion, got '%s'", metadata.NaGINIVersion)
	}

	if metadata.Author != "" {
		t.Errorf("Expected empty Author, got '%s'", metadata.Author)
	}

	if metadata.TemplateVersion != "" {
		t.Errorf("Expected empty TemplateVersion, got '%s'", metadata.TemplateVersion)
	}

	if metadata.Info != "" {
		t.Errorf("Expected empty Info, got '%s'", metadata.Info)
	}
}

func TestParseMetadataPartial(t *testing.T) {
	// Test script with partial metadata
	scriptContent := `#!/bin/bash
#@ Author: test user
#@ Info: Simple test script
# Some metadata is missing

echo "Installing Arch Linux..."
`

	metadata := ParseMetadata([]byte(scriptContent))

	// Check that only provided metadata is parsed
	if metadata.Author != "test user" {
		t.Errorf("Expected Author 'test user', got '%s'", metadata.Author)
	}

	if metadata.Info != "Simple test script" {
		t.Errorf("Expected Info 'Simple test script', got '%s'", metadata.Info)
	}

	// Missing fields should be empty
	if metadata.NaGINIVersion != "" {
		t.Errorf("Expected empty NaGINIVersion, got '%s'", metadata.NaGINIVersion)
	}

	if metadata.TemplateVersion != "" {
		t.Errorf("Expected empty TemplateVersion, got '%s'", metadata.TemplateVersion)
	}
}

func TestDecryptRejectsPlaintext(t *testing.T) {
	plain := []byte("#!/bin/bash\necho pwned\n")
	if out, err := Decrypt(plain, "some-passphrase"); err == nil || out != nil {
		t.Fatalf("expected error and no content, got %q, %v", out, err)
	}
}

func TestDecryptRequiresPassphrase(t *testing.T) {
	for _, content := range [][]byte{[]byte("#!/bin/bash\necho hi\n"), []byte("TkdOAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")} {
		if out, err := Decrypt(content, ""); err == nil || out != nil {
			t.Fatalf("expected error without passphrase, got %q, %v", out, err)
		}
	}
}

func TestCopyFileIsRootOnly(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.log")
	dst := filepath.Join(dir, "dst.log")
	if err := os.WriteFile(src, []byte("log"), 0644); err != nil {
		t.Fatal(err)
	}
	// Pre-existing world-readable destination must be tightened too
	if err := os.WriteFile(dst, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}
}
