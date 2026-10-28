package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// testDeviceUUID is the file system UUID of a removable disk in the tests.
const testDeviceUUID = "6f8a4d9e-2b1c-4e3f-9a7b-5c6d7e8f9a0b"

// newRemovableHarness is newDatastoreHarness with the lists of datastores
// and a connected removable disk.
func newRemovableHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeDatastores) {
	t.Helper()
	h, fake, datastores := newDatastoreHarness(t, version...)
	newFakeDatastoreStatus(datastores)
	datastores.connectDevice(testDeviceUUID, true)
	return h, fake, datastores
}

func TestDatastoreResourceRemovable(t *testing.T) {
	h, fake, datastores := newRemovableHarness(t)
	config := map[string]any{"name": "usb", "path": "pbs/usb", "backing_device": testDeviceUUID, "gc_schedule": "daily"}

	// A removable datastore's mount status is unknown until PBS says.
	planned := h.plan(t, "pbs_datastore", nil, h.resourceValue(t, "pbs_datastore", config))
	requireNoProtocolErrors(t, planned.Diagnostics)
	if !isUnknownAt(t, h.decodeResource(t, "pbs_datastore", planned.PlannedState), "mount_status") {
		t.Error("mount_status of a removable datastore is planned as known")
	}
	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", config))
	created := fake.lastCall(t, "POST /config/datastore")
	if created.form.Get("backing-device") != testDeviceUUID || created.form.Get("path") != "pbs/usb" || created.form.Has("gc-on-unmount") {
		t.Errorf("POST form = %v", created.form)
	}
	if stringAt(t, inst.state, "mount_status") != pbsclient.MountStatusMounted || stringAt(t, inst.state, "backing_device") != testDeviceUUID ||
		boolAt(t, inst.state, "gc_on_unmount") {
		t.Errorf("state = %s", inst.state)
	}
	if !datastores.isMounted("usb") {
		t.Error("PBS did not leave the new datastore mounted")
	}

	// A plan against the unchanged configuration changes nothing.
	replan := h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", config))
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_datastore", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// PBS unmounts it: a refresh reports that, and changes nothing else.
	datastores.setMounted("usb", false)
	datastores.setDatastoreProperty("usb", "maintenance-mode", "unmount")
	refreshed := h.refresh(t, inst)
	if stringAt(t, refreshed.state, "mount_status") != pbsclient.MountStatusNotMounted || !isNullAt(t, refreshed.state, "maintenance_mode") {
		t.Errorf("state after unmounting = %s", refreshed.state)
	}
	inst = refreshed
	datastores.setDatastoreProperty("usb", "maintenance-mode", nil)

	// Settings change while it is not mounted, gc_on_unmount among them.
	config["gc_on_unmount"] = true
	config["destroy_data"] = true
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", config))
	if got := fake.lastCall(t, "PUT /config/datastore/usb").form.Get("gc-on-unmount"); got != "true" {
		t.Errorf("PUT gc-on-unmount = %q", got)
	}
	if !boolAt(t, inst.state, "gc_on_unmount") || stringAt(t, inst.state, "mount_status") != pbsclient.MountStatusNotMounted {
		t.Errorf("state = %s", inst.state)
	}
	delete(config, "gc_on_unmount")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", config))
	if got := fake.lastCall(t, "PUT /config/datastore/usb").form["delete"]; len(got) != 1 || got[0] != "gc-on-unmount" {
		t.Errorf("PUT delete = %v, want gc-on-unmount reset by deleting it", got)
	}

	// destroy_data needs it mounted.
	null := tftypes.NewValue(h.resourceType(t, "pbs_datastore"), nil)
	planned = h.plan(t, "pbs_datastore", inst, null)
	applied := h.apply(t, "pbs_datastore", inst, null, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "proxmox-backup-manager datastore mount usb")
	if _, exists := datastores.datastore("usb"); !exists {
		t.Fatal("the datastore is gone")
	}
	datastores.setMounted("usb", true)
	h.destroy(t, inst)
	if datastores.hasChunkStore(testDeviceUUID + ":pbs/usb") {
		t.Error("destroy_data left the chunk store on the device")
	}
}

// PBS mounts the device to create the datastore, which fails while the disk
// is not connected.
func TestDatastoreResourceRemovableDisconnected(t *testing.T) {
	h, _, datastores := newRemovableHarness(t)
	datastores.connectDevice(testDeviceUUID, false)

	config := h.resourceValue(t, "pbs_datastore", map[string]any{"name": "usb", "path": "usb", "backing_device": testDeviceUUID})
	planned := h.plan(t, "pbs_datastore", nil, config)
	applied := h.apply(t, "pbs_datastore", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "could not mount the file system with UUID "+testDeviceUUID)
	if state := h.decodeResource(t, "pbs_datastore", applied.NewState); !state.IsNull() {
		t.Errorf("a failed create left state %s", state)
	}
}

// A removable datastore imports with its device, path and mount status; a
// datastore that is not removable needs no list to say it is not.
func TestDatastoreResourceRemovableImport(t *testing.T) {
	h, fake, datastores := newRemovableHarness(t)
	datastores.addDatastore("usb", fakeProperties{"path": "usb", "backing-device": testDeviceUUID, "gc-on-unmount": true})
	datastores.addDatastore("store1", fakeProperties{"path": "/mnt/datastore/store1"})

	inst := h.importByID(t, "pbs_datastore", "usb")
	if stringAt(t, inst.state, "path") != "usb" || stringAt(t, inst.state, "backing_device") != testDeviceUUID ||
		!boolAt(t, inst.state, "gc_on_unmount") || stringAt(t, inst.state, "mount_status") != pbsclient.MountStatusNotMounted {
		t.Errorf("import = %s", inst.state)
	}

	lists := fake.count("GET /admin/datastore")
	inst = h.importByID(t, "pbs_datastore", "store1")
	if stringAt(t, inst.state, "mount_status") != pbsclient.MountStatusNonRemovable || !isNullAt(t, inst.state, "backing_device") {
		t.Errorf("import = %s", inst.state)
	}
	if fake.count("GET /admin/datastore") != lists {
		t.Error("listed the datastores for one that is not removable")
	}

	// When the list fails, the mount status is left empty, with a warning.
	fake.reply("GET /admin/datastore", 403, "permission check failed")
	resp := h.importResource(t, "pbs_datastore", "usb", nil)
	imported := resp.ImportedResources[0]
	read := h.read(t, &resourceInstance{typeName: "pbs_datastore", state: h.decodeResource(t, "pbs_datastore", imported.State), identity: imported.Identity})
	requireNoProtocolErrors(t, read.Diagnostics)
	requireProtocolWarningContaining(t, read.Diagnostics, "mount status of removable datastore")
	if state := h.decodeResource(t, "pbs_datastore", read.NewState); !isNullAt(t, state, "mount_status") {
		t.Errorf("state = %s", state)
	}
}

// A datastore that is not removable is planned as such; gc_on_unmount needs
// PBS 4.2; and a new name on the same device and path needs reuse_datastore,
// as one in the same directory does.
func TestDatastoreResourceRemovablePlan(t *testing.T) {
	h, _, _ := newRemovableHarness(t)
	planned := h.plan(t, "pbs_datastore", nil, h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store1", "path": "/mnt/s1"}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, "pbs_datastore", planned.PlannedState), "mount_status"); got != pbsclient.MountStatusNonRemovable {
		t.Errorf("planned mount_status = %q", got)
	}

	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{"name": "usb", "path": "usb", "backing_device": testDeviceUUID}))
	renamed := map[string]any{"name": "usb2", "path": "usb", "backing_device": testDeviceUUID}
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", renamed))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Set reuse_datastore = true")
	renamed["backing_device"] = "00000000-0000-4000-8000-000000000000"
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", renamed))
	requireNoProtocolErrors(t, planned.Diagnostics)

	old, _, _ := newRemovableHarness(t, fakeVersion40)
	config := map[string]any{"name": "usb", "path": "usb", "backing_device": testDeviceUUID, "gc_on_unmount": true}
	planned = old.plan(t, "pbs_datastore", nil, old.resourceValue(t, "pbs_datastore", config))
	requireProtocolErrorContaining(t, planned.Diagnostics, "gc_on_unmount needs PBS 4.2 or newer")
	config["gc_on_unmount"] = false
	planned = old.plan(t, "pbs_datastore", nil, old.resourceValue(t, "pbs_datastore", config))
	requireNoProtocolErrors(t, planned.Diagnostics)
}
