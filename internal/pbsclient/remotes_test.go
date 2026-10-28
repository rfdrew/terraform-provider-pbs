package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// A read leaves out the port at its default and never has the password.
func TestGetRemoteDecodesTheRemote(t *testing.T) {
	port := int64(8008)
	yes := true
	const fingerprint = "64:d3:ff:3a:50:38:53:5a:9e:2b:1f:6a:5a:1d:4a:42:7c:61:4b:01:f2:15:97:9a:2e:1d:ac:1b:7d:0e:aa:17"
	tests := map[string]struct {
		answer string
		want   Remote
	}{
		"defaults left out": {
			`{"data":{"name":"offsite","host":"pbs2.example.com","auth-id":"sync@pbs"},"digest":"9f86d081884c7d65"}`,
			Remote{Name: "offsite", Host: "pbs2.example.com", AuthID: "sync@pbs"},
		},
		"every property": {
			`{"data":{"name":"offsite","host":"2001:db8::2","port":8008,"auth-id":"sync@pbs!offsite","fingerprint":"` + fingerprint +
				`","use-node-proxy":true,"comment":"acc"},"digest":"9f86d081884c7d65"}`,
			Remote{Name: "offsite", Host: "2001:db8::2", Port: &port, AuthID: "sync@pbs!offsite", Fingerprint: fingerprint,
				UseNodeProxy: &yes, Comment: "acc"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/remote/offsite", http.StatusOK, tc.answer)
			remote, err := fake.client(t).GetRemote(context.Background(), "offsite")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(remote, tc.want) {
				t.Fatalf("GetRemote() = %+v, want %+v", remote, tc.want)
			}
		})
	}
}

// The writes send the caller's params as the form; the delete names the
// remote in its path and sends nothing else; the scans name the remote and
// the datastore.
func TestRemoteCallsHitTheirRoutes(t *testing.T) {
	const (
		listRoute       = "GET /config/remote"
		createRoute     = "POST /config/remote"
		updateRoute     = "PUT /config/remote/offsite"
		deleteRoute     = "DELETE /config/remote/offsite"
		scanRoute       = "GET /config/remote/offsite/scan"
		namespacesRoute = "GET /config/remote/offsite/scan/store1/namespaces"
	)
	fake := newFakePBS()
	fake.reply(listRoute, http.StatusOK, `{"data":[{"name":"offsite","host":"pbs2.example.com","auth-id":"sync@pbs"},`+
		`{"name":"lab","host":"192.0.2.7","port":8007,"auth-id":"root@pam"}],"digest":"9f86d081884c7d65"}`)
	fake.reply(createRoute, http.StatusOK, `{"data":null}`)
	fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
	fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
	fake.reply(scanRoute, http.StatusOK, `{"data":[{"store":"store1","comment":"Backups","mount-status":"nonremovable",`+
		`"backend-type":"filesystem"},{"store":"store2","maintenance":"read-only"}]}`)
	fake.reply(namespacesRoute, http.StatusOK, `{"data":[{"ns":""},{"ns":"dept1","comment":"Department 1"},{"ns":"dept1/hosts"}]}`)
	c := fake.client(t)
	ctx := context.Background()

	remotes, err := c.ListRemotes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := int64(8007)
	wantRemotes := []Remote{
		{Name: "offsite", Host: "pbs2.example.com", AuthID: "sync@pbs"},
		{Name: "lab", Host: "192.0.2.7", Port: &port, AuthID: "root@pam"},
	}
	if !reflect.DeepEqual(remotes, wantRemotes) {
		t.Fatalf("ListRemotes() = %+v, want %+v", remotes, wantRemotes)
	}

	create := url.Values{"name": {"offsite"}, "host": {"pbs2.example.com"}, "auth-id": {"sync@pbs"}, "password": {"s3cr3t"}}
	if err := c.CreateRemote(ctx, create); err != nil {
		t.Fatalf("CreateRemote() = %v", err)
	}
	update := url.Values{"port": {"8008"}, "password": {"n3w"}, "delete": {"comment", "fingerprint"}}
	if err := c.UpdateRemote(ctx, "offsite", update); err != nil {
		t.Fatalf("UpdateRemote() = %v", err)
	}
	datastores, err := c.ScanRemoteDatastores(ctx, "offsite")
	if err != nil {
		t.Fatal(err)
	}
	wantDatastores := []RemoteDatastore{
		{Store: "store1", Comment: "Backups", MountStatus: "nonremovable", BackendType: "filesystem"},
		{Store: "store2", Maintenance: "read-only"},
	}
	if !reflect.DeepEqual(datastores, wantDatastores) {
		t.Fatalf("ScanRemoteDatastores() = %+v, want %+v", datastores, wantDatastores)
	}
	namespaces, err := c.ScanRemoteNamespaces(ctx, "offsite", "store1")
	if err != nil {
		t.Fatal(err)
	}
	wantNamespaces := []RemoteNamespace{{NS: ""}, {NS: "dept1", Comment: "Department 1"}, {NS: "dept1/hosts"}}
	if !reflect.DeepEqual(namespaces, wantNamespaces) {
		t.Fatalf("ScanRemoteNamespaces() = %+v, want %+v", namespaces, wantNamespaces)
	}
	if err := c.DeleteRemote(ctx, "offsite"); err != nil {
		t.Fatalf("DeleteRemote() = %v", err)
	}

	want := []string{listRoute, createRoute, updateRoute, scanRoute, namespacesRoute, deleteRoute}
	if got := fake.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, createRoute); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreateRemote form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, updateRoute); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdateRemote form = %v, want %v", call.form, update)
	}
	for _, route := range []string{deleteRoute, scanRoute, namespacesRoute} {
		if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v, want neither", route, call.query, call.form)
		}
	}
}

// The password is a secret the client does not otherwise hold, so both
// writes keep it out of their errors.
func TestRemoteWritesRedactThePassword(t *testing.T) {
	const password = `r3m0te "pa55"`
	const echo = `parameter verification failed - 'password': value "r3m0te \"pa55\"" rejected`
	tests := map[string]struct {
		route string
		write func(*Client, url.Values) error
	}{
		"create": {"POST /config/remote", func(c *Client, params url.Values) error {
			return c.CreateRemote(context.Background(), params)
		}},
		"update": {"PUT /config/remote/offsite", func(c *Client, params url.Values) error {
			return c.UpdateRemote(context.Background(), "offsite", params)
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(tc.route, http.StatusBadRequest, echo)
			err := tc.write(fake.client(t), url.Values{"name": {"offsite"}, "password": {password}})
			apiErr, ok := asError(err)
			if !ok || apiErr.StatusCode != http.StatusBadRequest {
				t.Fatalf("error = %v, want PBS's 400", err)
			}
			if strings.Contains(err.Error(), "pa55") || strings.Contains(apiErr.Body, "pa55") || !strings.Contains(err.Error(), redactedMarker) {
				t.Fatalf("error = %v, body = %q", err, apiErr.Body)
			}
		})
	}
}

// A missing remote is a 400 on read and a 404 on delete; a taken name and a
// remote that sync jobs use are 400s the provider tells apart.
func TestRemoteErrorsAreRecognised(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/remote/missing", http.StatusBadRequest, "no such remote 'missing'")
	fake.reply("DELETE /config/remote/missing", http.StatusNotFound, "remote 'missing' does not exist.")
	fake.reply("DELETE /config/remote/used", http.StatusBadRequest,
		"parameter verification failed - 'name': remote 'used' is used by sync job 'pull1' (datastore 'store1')")
	fake.reply("POST /config/remote", http.StatusBadRequest, "parameter verification failed - 'name': remote 'taken' already exists.")
	c := fake.client(t)
	ctx := context.Background()

	if remote, err := c.GetRemote(ctx, "missing"); !IsNotFound(err) || IsRemoteInUse(err) || remote != (Remote{}) {
		t.Errorf("GetRemote() = %+v, %v, want only a not-found error", remote, err)
	}
	if err := c.DeleteRemote(ctx, "missing"); !IsNotFound(err) || IsRemoteInUse(err) {
		t.Errorf("DeleteRemote(missing) = %v, want a not-found error", err)
	}
	if err := c.DeleteRemote(ctx, "used"); !IsRemoteInUse(err) || IsNotFound(err) {
		t.Errorf("DeleteRemote(used) = %v, want an in-use error", err)
	}
	if err := c.CreateRemote(ctx, url.Values{"name": {"taken"}}); !IsAlreadyExists(err) || IsRemoteInUse(err) {
		t.Errorf("CreateRemote() = %v, want an already-exists error", err)
	}
	if IsRemoteInUse(nil) {
		t.Error("IsRemoteInUse(nil) = true")
	}
}
