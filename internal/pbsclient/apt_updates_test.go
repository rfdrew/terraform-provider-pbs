package pbsclient

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// PBS 4.2.8 leaves OldVersion out for a package an upgrade would install
// anew, PBS 4.0 before 4.0.20 sent "", and null decodes the same.
func TestAPTUpdatesDecodesPascalCaseKeys(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/pbs1/apt/update", http.StatusOK, `{"data":[
		{"Arch":"amd64","Description":"Daemons and tools.\nWith a GUI.","OldVersion":"4.2.7","Origin":"Proxmox",
		 "Package":"proxmox-backup-server","Priority":"optional","Section":"admin","Title":"Proxmox Backup Server daemon with tools and GUI","Version":"4.2.8"},
		{"Arch":"amd64","Description":"","Origin":"Proxmox","Package":"proxmox-kernel-6.17.2-1-pve-signed",
		 "Priority":"optional","Section":"kernel","Title":"Proxmox Kernel Image (signed)","Version":"6.17.2-1"},
		{"Arch":"all","Description":"","OldVersion":"","Origin":"unknown","Package":"a","Priority":"unknown","Section":"unknown","Title":"a","Version":"1"},
		{"Arch":"all","Description":"","OldVersion":null,"Origin":"unknown","Package":"b","Priority":"unknown","Section":"unknown","Title":"b","Version":"2"}]}`)
	c := fake.client(t)

	updates, err := c.APTUpdates(context.Background(), "pbs1")
	if err != nil {
		t.Fatal(err)
	}
	want := []APTUpdate{
		{Package: "proxmox-backup-server", Title: "Proxmox Backup Server daemon with tools and GUI", Arch: "amd64",
			Description: "Daemons and tools.\nWith a GUI.", Version: "4.2.8", OldVersion: "4.2.7",
			Origin: "Proxmox", Priority: "optional", Section: "admin"},
		{Package: "proxmox-kernel-6.17.2-1-pve-signed", Title: "Proxmox Kernel Image (signed)", Arch: "amd64",
			Version: "6.17.2-1", Origin: "Proxmox", Priority: "optional", Section: "kernel"},
		{Package: "a", Title: "a", Arch: "all", Version: "1", Origin: "unknown", Priority: "unknown", Section: "unknown"},
		{Package: "b", Title: "b", Arch: "all", Version: "2", Origin: "unknown", Priority: "unknown", Section: "unknown"},
	}
	if !reflect.DeepEqual(updates, want) {
		t.Errorf("APTUpdates() = %+v, want %+v", updates, want)
	}
}

func TestAPTUpdatesReturnsTheError(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/apt/update", http.StatusForbidden, "permission check failed")

	if _, err := fake.client(t).APTUpdates(context.Background(), "localhost"); !IsForbidden(err) {
		t.Errorf("APTUpdates() error = %v, want 403", err)
	}
}
