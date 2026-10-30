#!/usr/bin/env bash
#
# Boots a throwaway Proxmox Backup Server for the acceptance tests and prints
# the PBS_* exports on stdout.
#
# Proxmox publishes no container image for PBS, so the script supports two
# stands, picked with PBS_TEST_VARIANT:
#
#   * packages (default, and what CI runs): the official
#     proxmox-backup-server package from the pbs-no-subscription repository,
#     installed into a Debian trixie image that boots systemd as PID 1 in a
#     privileged container. Closest to a real installation, and root@pam
#     works — some calls, such as creating a network interface, are open to
#     root@pam only. The image is built on first use; PBS_TEST_PBS_VERSION
#     pins the release.
#   * image: ayufan/proxmox-backup-server, a community image that runs
#     proxmox-backup-api and proxmox-backup-proxy under runit, for a quick
#     local stand without a privileged container. No systemd, no PAM and no
#     ZFS; the only account is admin@pbs (password pbspbs), an Admin on / but
#     not the superuser, and the image lags behind PBS releases.
#
# Once the API answers, the script logs in as the admin and creates
#
#   * a datastore $PBS_TEST_DATASTORE under /datastore, a Docker volume,
#   * the user tfacc@pbs with a password, and its API token tfacc@pbs!acc,
#   * an Admin ACL on / for both (a token has no privileges of its own),
#
# and starts Pebble, Let's Encrypt's test CA, in the PBS container's network
# namespace, as the ACME directory https://localhost:14000/dir for PBS. Pebble
# validates every challenge without looking (PEBBLE_VA_ALWAYS_VALID), so
# ordering a certificate needs neither DNS nor a reachable port 80. It also
# starts an S3 server, Silo (a maintained fork of MinIO, whose own images are
# gone), in the same network namespace at https://127.0.0.1:9000, with the
# buckets tfacc-s3 and tfacc-s3-spare, for the S3 endpoint and S3 datastore
# tests. The packages stand also gets a file system on a loop device, for
# removable datastores.
#
# For the LDAP and Active Directory realms, it starts an OpenLDAP server,
# slapd from Debian's package, the same way, in a container of its own in the
# PBS container's network namespace: PBS reaches it at 127.0.0.1, with plain
# LDAP and StartTLS on port 389 and LDAPS on 636. The directory has a bind
# account and a user, alice, whose entry also carries the sAMAccountName an
# Active Directory realm looks users up by; its root DSE names the base DN as
# defaultNamingContext, as a domain controller does. Anonymous clients read
# the root DSE and the schema, and nothing else.
#
# It then prints what the provider reads — PBS_ENDPOINT, PBS_API_TOKEN and
# PBS_TLS_FINGERPRINT — and the PBS_ACC_* facts the tests need: the test
# user's password, the admin account, the datastore, the container, the
# variant, the PBS version, the ACME directory, the files of PBS's own
# certificate and key, which the certificate tests put back when they end,
# the UUID of the file system for removable datastores, the address at
# which the container reaches this host, where the notification tests
# receive what PBS sends, the S3 server's address, port, region, keys,
# certificate fingerprint, buckets and container, and the LDAP server: the
# address PBS connects to, the base DN, the bind account and its password,
# the user and its password, and the file of the CA that signed the
# server's certificate, in the PBS container.
# The test user's credentials are not exported as PBS_USERNAME and
# PBS_PASSWORD, which the provider would read alongside the token.
#
# Things this script has to get right for PBS:
#
#   * the proxy accepts TCP before the API daemon serves, and without auth
#     every call answers 401. Readiness is therefore a real login
#     (POST /access/ticket), and every curl has a timeout.
#   * a ticket needs the CSRFPreventionToken header on every write; an API
#     token needs none. The token header is
#     "Authorization: PBSAPIToken=<user>@<realm>!<name>:<secret>".
#   * a datastore needs a directory the backup user can write to; PBS creates
#     it, with its 65536 chunk directories, below /datastore.
#   * the TLS certificate is self-signed and generated at the first start;
#     its fingerprint is read from GET /nodes/localhost/certificates/info and,
#     with openssl, checked against what the port actually serves.
#   * the ayufan image runs proxmox-backup-proxy only after the API daemon
#     has written csrf.key, and needs /run on tmpfs.
#   * systemd as PID 1 needs a privileged container with the host's cgroup
#     namespace; the root password is set with chpasswd after the boot.
#   * Docker bind-mounts /etc/resolv.conf, and PBS writes it by renaming a
#     new file over it, which fails on a mount point. The packages stand
#     unmounts it, keeping its content, so that DNS settings can be tested.
#   * PBS talks to an ACME directory over HTTPS and verifies it against the
#     system's CAs. Pebble's image ships a certificate for its directory that
#     expires in October 2027, so the script gives Pebble a certificate of its
#     own, signed by a throwaway CA, which goes into the PBS container's trust
#     store; Pebble shares the PBS container's network, where the
#     certificate's name, localhost, is right. Pebble rejects 5% of nonces
#     unless told not to, which PBS retries only three times.
#   * PBS mounts a removable datastore's file system with `mount UUID=<uuid>`
#     and tells whether it is mounted by comparing the device numbers of
#     /dev/disk/by-uuid/<uuid> and of the mount's source. The packages stand
#     has an ext4 image on a loop device for that, and the by-uuid link udev
#     would make on a host. Loop devices belong to the host's kernel: the
#     privileged container sees the device nodes the host had when it
#     started, so the script creates the node of a newer one, and detaches
#     the device again when it removes the container.
#   * PBS talks to S3 over HTTPS only and never creates buckets. It accepts
#     the server's certificate when OpenSSL trusts it and, only failing that,
#     when the certificate's SHA-256 fingerprint matches the endpoint's. So
#     the S3 server's certificate is self-signed and not signed by the test
#     CA PBS trusts for Pebble: a trusted certificate would let any
#     fingerprint pass. The buckets are made with mc in the S3 container.
#   * The S3 server has no region of its own, so it accepts any region PBS
#     signs with; PBS defaults to us-west-1. Requests use path style, as the
#     endpoint is an IP address.
#   * PBS connects to an LDAP server whenever a realm is created or changed,
#     from its own host, so slapd shares the PBS container's network
#     namespace. It listens on 127.0.0.1 only, not on every address: Linux
#     routes all of 127.0.0.0/8 to the loopback interface, so 127.0.0.2
#     refuses connections, which the tests take for a server that is down.
#   * with TLS and verify, PBS checks the server's certificate and its name,
#     the address it connects to. The certificate names DNS:localhost and
#     IP:127.0.0.1 and is signed by a throwaway CA of its own, not Pebble's,
#     which PBS does not trust unless a realm's capath names it: the CA's
#     certificate is the only file in its directory in the PBS container, so
#     that the directory works as a capath too — PBS reads every file of a
#     capath directory as a certificate. Debian's slapd links OpenSSL, as of
#     trixie; the server key is RSA all the same, which any TLS library takes.
#   * Debian's slapd package sets up a database of its own when it is
#     installed, unless debconf is told slapd/no_configuration; slapd then
#     runs in the foreground from a slapd.conf the script copies in, after
#     slapadd has loaded the directory. The image is built on first use, but
#     CI caches only the PBS image, so there the LDAP image is built on every
#     run, in about half a minute.
#   * OpenLDAP lets no schema file define an operational attribute, so
#     defaultNamingContext is a user attribute of a small schema of the
#     script's own, along with Microsoft's sAMAccountName; slapd adds it to
#     the root DSE from an LDIF file (rootDSE). PBS asks the root DSE
#     anonymously.
#
# Usage:
#   eval "$(scripts/bootstrap-test-pbs.sh)"                         # official packages
#   eval "$(PBS_TEST_VARIANT=image scripts/bootstrap-test-pbs.sh)"  # ayufan image
#   scripts/bootstrap-test-pbs.sh --teardown                        # removes container, volumes and state
#
# Settings, all optional:
#   PBS_TEST_VARIANT         packages (default) or image
#   PBS_TEST_IMAGE           image for the image variant
#                            (default ayufan/proxmox-backup-server:v4.2.0-1)
#   PBS_TEST_BASE_IMAGE      base image for the packages variant (default debian:trixie)
#   PBS_TEST_PBS_VERSION     packages variant: install the newest proxmox-backup-server
#                            whose version starts with this (e.g. 4.0); default the newest
#   PBS_TEST_CONTAINER       container name (default pbs-tfprovider-test)
#   PBS_TEST_PORT            host port, bound to 127.0.0.1 only (default 8007)
#   PBS_TEST_DATASTORE       datastore to create (default tfacc)
#   PBS_TEST_WAIT_SECONDS    how long to wait for the API (default 180)
#   PBS_TEST_STATE_DIR       where credentials are kept
#   PBS_TEST_PEBBLE          set to 0 to start no Pebble; the ACME tests then skip
#   PBS_TEST_PEBBLE_IMAGE    Pebble image (default ghcr.io/letsencrypt/pebble:2.10.1)
#   PBS_TEST_S3              set to 0 to start no S3 server; the S3 tests then skip
#   PBS_TEST_S3_IMAGE        S3 server image (default pgsty/silo:RELEASE.2026-09-16T00-00-00Z)
#   PBS_TEST_S3_PORT         port of the S3 server in PBS's network namespace (default 9000)
#   PBS_TEST_REMOVABLE       packages variant: set to 0 to make no file system for
#                            removable datastores; their tests then skip
#   PBS_TEST_LDAP            set to 0 to start no LDAP server; the LDAP and Active
#                            Directory realm tests then skip
#   PBS_TEST_LDAP_BASE_IMAGE base image of the LDAP server's image
#                            (default debian:trixie-slim)
#
# The script logs "timing: <phase> <seconds>s" lines on stderr, so that CI can
# report how long the stand takes to come up.
#
# On failure the script prints `false` on stdout, so that the eval above fails
# too instead of silently exporting nothing — `eval "$(...)"` otherwise returns
# 0 whatever the script's exit status was.
#
# Everything it creates is disposable; never point this at a real server.
set -euo pipefail

VARIANT="${PBS_TEST_VARIANT:-packages}"
IMAGE="${PBS_TEST_IMAGE:-ayufan/proxmox-backup-server:v4.2.0-1}"
BASE_IMAGE="${PBS_TEST_BASE_IMAGE:-debian:trixie}"
PBS_VERSION="${PBS_TEST_PBS_VERSION:-}"
PACKAGES_IMAGE="pbs-tfprovider-test-packages:${BASE_IMAGE##*:}${PBS_VERSION:+-$PBS_VERSION}"
CONTAINER="${PBS_TEST_CONTAINER:-pbs-tfprovider-test}"
PORT="${PBS_TEST_PORT:-8007}"
DATASTORE="${PBS_TEST_DATASTORE:-tfacc}"
DATASTORE_DIR="/datastore"
WAIT_SECONDS="${PBS_TEST_WAIT_SECONDS:-180}"
STATE_DIR="${PBS_TEST_STATE_DIR:-${TMPDIR:-/tmp}/${CONTAINER}}"
VOLUMES=("${CONTAINER}-etc" "${CONTAINER}-lib" "${CONTAINER}-log" "${CONTAINER}-datastore")
PEBBLE="${PBS_TEST_PEBBLE:-1}"
PEBBLE_IMAGE="${PBS_TEST_PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:2.10.1}"
PEBBLE_CONTAINER="${CONTAINER}-pebble"
ACME_DIRECTORY="https://localhost:14000/dir"
REMOVABLE="${PBS_TEST_REMOVABLE:-1}"
# The image of the file system for removable datastores, in the container,
# and the file that notes its loop device, for the teardown.
REMOVABLE_IMAGE="/var/lib/proxmox-backup/tfacc-removable.img"
REMOVABLE_LOOP_FILE="/var/lib/proxmox-backup/tfacc-removable.loop"
REMOVABLE_UUID=""
S3="${PBS_TEST_S3:-1}"
S3_IMAGE="${PBS_TEST_S3_IMAGE:-pgsty/silo:RELEASE.2026-09-16T00-00-00Z}"
S3_CONTAINER="${CONTAINER}-s3"
# PBS reaches the server over the shared loopback. An IP address needs no
# name resolution, and PBS sends no SNI for it.
S3_ENDPOINT="127.0.0.1"
S3_PORT="${PBS_TEST_S3_PORT:-9000}"
# Offered to the tests; the server itself accepts any region.
S3_REGION="us-east-1"
# The first bucket is the one the datastore tests use; every bucket is
# listed by list-buckets, and PBS fails to parse an empty bucket list.
S3_BUCKETS=(tfacc-s3 tfacc-s3-spare)
# mc's name for the server in its container, left there for the tests.
S3_MC_ALIAS="tfacc"
# The endpoint the script creates in PBS to try the server, and removes.
S3_PROBE_ID="tfacc-s3-probe"
S3_FINGERPRINT=""

# The LDAP server: its container, the address PBS connects to, the
# directory, and where the files go — slapd's, in the LDAP container, and the
# CA's certificate, alone in its directory, in the PBS container. The image
# and the passwords are set when the server starts.
LDAP="${PBS_TEST_LDAP:-1}"
LDAP_BASE_IMAGE="${PBS_TEST_LDAP_BASE_IMAGE:-debian:trixie-slim}"
LDAP_CONTAINER="${CONTAINER}-ldap"
LDAP_SERVER="127.0.0.1"
LDAP_BASE_DN="dc=example,dc=org"
LDAP_BIND_DN="cn=pbs-bind,ou=services,${LDAP_BASE_DN}"
LDAP_USER="alice"
LDAP_USER_DN="uid=${LDAP_USER},ou=people,${LDAP_BASE_DN}"
LDAP_CONFIG_DIR="/etc/ldap/tfacc"
LDAP_CA_FILE="/usr/local/share/tfacc-ldap/ca.pem"
LDAP_IMAGE=""
LDAP_BIND_PASS=""
LDAP_USER_PASS=""

TEST_USER="tfacc@pbs"
TEST_TOKEN_NAME="acc"

log() { echo "$*" >&2; }

# Traffic to the container must never go through HTTP(S)_PROXY or ALL_PROXY,
# and the certificate is self-signed: curl only bootstraps here, pinning the
# fingerprint is the provider's job.
curl() { command curl --noproxy '*' -k --connect-timeout 2 --max-time 30 "$@"; }

base_url() { echo "https://127.0.0.1:${PORT}"; }
api_url() { echo "$(base_url)/api2/json$1"; }

rand_hex() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }

T0="$(date +%s)"
timing() { log "timing: $1 $(($(date +%s) - $2))s"; }

# release_removable_device detaches the loop device of the file system for
# removable datastores, which would outlive the container otherwise. One that
# a mount in the container still holds is detached when the container's
# mounts go with it. A stopped container that has a loop device noted is
# started for that: docker exec needs it running.
release_removable_device() {
  if ! docker cp "${CONTAINER}:${REMOVABLE_LOOP_FILE}" - >/dev/null 2>&1; then
    return 0
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != "true" ]]; then
    docker start "$CONTAINER" >/dev/null 2>&1 || return 0
  fi
  # shellcheck disable=SC2016 # expanded by the container's shell
  docker exec "$CONTAINER" sh -c 'dev="$(cat "$1")"; [ -b "$dev" ] || mknod "$dev" b 7 "${dev#/dev/loop}"; losetup -d "$dev"' \
    sh "$REMOVABLE_LOOP_FILE" >/dev/null 2>&1 || true
}

if [[ "${1:-}" == "--teardown" ]]; then
  # The containers sharing PBS's network go before the one that owns it.
  docker rm -f -v "$PEBBLE_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f -v "$S3_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f -v "$LDAP_CONTAINER" >/dev/null 2>&1 || true
  release_removable_device
  docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm -f "${VOLUMES[@]}" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
  log "removed $CONTAINER, $PEBBLE_CONTAINER, $S3_CONTAINER, $LDAP_CONTAINER, the volumes and $STATE_DIR"
  exit 0
fi

trap 'status=$?; if [[ $status -ne 0 ]]; then echo false; fi' EXIT

command -v docker >/dev/null || { log "docker not found"; exit 1; }
command -v jq >/dev/null || { log "jq not found"; exit 1; }
if [[ "$PEBBLE" != "0" || "$S3" != "0" ]]; then
  command -v openssl >/dev/null || { log "openssl not found; it makes the certificates of Pebble and the S3 server (PBS_TEST_PEBBLE=0 PBS_TEST_S3=0 start neither)"; exit 1; }
fi
if [[ "$LDAP" != "0" ]]; then
  command -v openssl >/dev/null || { log "openssl not found; it makes the LDAP server's certificate (PBS_TEST_LDAP=0 starts no LDAP server)"; exit 1; }
fi

case "$VARIANT" in
  image)
    ADMIN_USER="admin@pbs"
    ADMIN_PASS="pbspbs"
    ;;
  packages)
    ADMIN_USER="root@pam"
    ADMIN_PASS="root-$(rand_hex)"
    ;;
  *)
    log "unknown PBS_TEST_VARIANT '$VARIANT': use image or packages"
    exit 1
    ;;
esac
TEST_PASS="tfacc-$(rand_hex)"
# The S3 server's only account. MinIO wants at least 3 characters for the
# access key and 8 for the secret.
S3_ACCESS_KEY="tfacc-$(rand_hex | cut -c1-12)"
S3_SECRET_KEY="$(rand_hex)"
case "$S3_PORT" in
  82 | 8007 | 5001 | 5002 | 14000 | 15000 | 389 | 636)
    log "PBS_TEST_S3_PORT=$S3_PORT is taken in PBS's network namespace (PBS: 82, 8007; Pebble: 5001, 5002, 14000, 15000; LDAP: 389, 636)"
    exit 1
    ;;
esac

container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)" == "true" ]]
}

dump_logs() {
  log "--- docker logs $CONTAINER (tail)"
  docker logs --tail 100 "$CONTAINER" >&2 2>&1 || true
  if docker inspect "$PEBBLE_CONTAINER" >/dev/null 2>&1; then
    log "--- docker logs $PEBBLE_CONTAINER (tail)"
    docker logs --tail 50 "$PEBBLE_CONTAINER" >&2 2>&1 || true
  fi
  if docker inspect "$S3_CONTAINER" >/dev/null 2>&1; then
    log "--- docker logs $S3_CONTAINER (tail)"
    docker logs --tail 50 "$S3_CONTAINER" >&2 2>&1 || true
  fi
  if docker inspect "$LDAP_CONTAINER" >/dev/null 2>&1; then
    log "--- docker logs $LDAP_CONTAINER (tail)"
    docker logs --tail 50 "$LDAP_CONTAINER" >&2 2>&1 || true
  fi
  if [[ "$VARIANT" == "packages" ]]; then
    log "--- journal of the PBS services (tail)"
    docker exec "$CONTAINER" journalctl --no-pager -n 100 \
      -u proxmox-backup.service -u proxmox-backup-proxy.service >&2 2>&1 || true
  fi
}

# The packages image: Debian with systemd, the Proxmox archive keyring and the
# pbs-no-subscription repository, and proxmox-backup-server installed. Package
# scripts do not start services during a build; systemd starts the enabled
# units when the container boots.
build_packages_image() {
  local ctx
  if docker image inspect "$PACKAGES_IMAGE" >/dev/null 2>&1; then
    log "reusing image $PACKAGES_IMAGE"
    return 0
  fi
  ctx="$(mktemp -d)"
  # The version is picked from `apt-cache madison`, which the build log shows,
  # so that the log also tells which releases the repository still serves.
  # proxmox-backup-client comes along to write test backups, and e2fsprogs
  # to make the file system for removable datastores.
  cat >"$ctx/Dockerfile" <<EOF
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \\
 && apt-get install -y --no-install-recommends ca-certificates curl systemd systemd-sysv \\
 && curl -fsSL -o /usr/share/keyrings/proxmox-archive-keyring.gpg \\
      https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg \\
 && printf '%s\n' 'Types: deb' 'URIs: http://download.proxmox.com/debian/pbs' 'Suites: trixie' \\
      'Components: pbs-no-subscription' 'Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg' \\
      >/etc/apt/sources.list.d/proxmox.sources \\
 && apt-get update \\
 && apt-cache madison proxmox-backup-server \\
 && v="\$(apt-cache madison proxmox-backup-server | awk -v p='${PBS_VERSION}' 'index(\$3, p) == 1 { print \$3; exit }')" \\
 && test -n "\$v" \\
 && echo "installing proxmox-backup-server=\$v" \\
 && apt-get install -y --no-install-recommends "proxmox-backup-server=\$v" proxmox-backup-client e2fsprogs \\
 && apt-get clean \\
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
  log "building $PACKAGES_IMAGE from $BASE_IMAGE"
  docker build --progress=plain -t "$PACKAGES_IMAGE" "$ctx" >&2
  rm -rf "$ctx"
}

start_image() {
  log "starting $IMAGE as $CONTAINER on $(base_url)"
  docker run -d \
    --name "$CONTAINER" \
    --hostname pbs-acc \
    --tmpfs /run \
    -p "127.0.0.1:${PORT}:8007" \
    --add-host host.docker.internal:host-gateway \
    -v "${CONTAINER}-etc:/etc/proxmox-backup" \
    -v "${CONTAINER}-lib:/var/lib/proxmox-backup" \
    -v "${CONTAINER}-log:/var/log/proxmox-backup" \
    -v "${CONTAINER}-datastore:${DATASTORE_DIR}" \
    "$IMAGE" >/dev/null
}

start_packages() {
  log "starting $PACKAGES_IMAGE as $CONTAINER on $(base_url)"
  docker run -d \
    --name "$CONTAINER" \
    --hostname pbs-acc \
    --privileged \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run \
    --tmpfs /run/lock \
    --tmpfs /tmp \
    -p "127.0.0.1:${PORT}:8007" \
    --add-host host.docker.internal:host-gateway \
    -v "${CONTAINER}-datastore:${DATASTORE_DIR}" \
    "$PACKAGES_IMAGE" >/dev/null
}

check_deadline() {
  if ! container_running; then
    log "container $CONTAINER is not running"
    dump_logs
    exit 1
  fi
  if [[ "$(date +%s)" -ge "$1" ]]; then
    log "PBS was not ready after ${WAIT_SECONDS}s at $(base_url): $2"
    dump_logs
    exit 1
  fi
}

# Waits until the proxy answers at all (401 without credentials), then until
# the admin can log in, which needs the API daemon behind the proxy.
TICKET=""
CSRF=""
wait_ready() {
  local deadline code body
  deadline=$(($(date +%s) + WAIT_SECONDS))
  while :; do
    check_deadline "$deadline" "no HTTP answer from GET /version"
    code="$(curl -s -o /dev/null -w '%{http_code}' "$(api_url /version)" 2>/dev/null)" || true
    case "${code:-000}" in
      200 | 401) break ;;
      *) sleep 1 ;;
    esac
  done
  timing "start-to-http" "$START"
  while :; do
    check_deadline "$deadline" "the admin could not log in"
    body="$(curl -s --data-urlencode "username=${ADMIN_USER}" --data-urlencode "password=${ADMIN_PASS}" \
      "$(api_url /access/ticket)" 2>/dev/null)" || true
    TICKET="$(jq -r '.data.ticket // empty' <<<"$body" 2>/dev/null)" || true
    CSRF="$(jq -r '.data.CSRFPreventionToken // empty' <<<"$body" 2>/dev/null)" || true
    if [[ -n "$TICKET" && -n "$CSRF" ]]; then
      break
    fi
    sleep 1
  done
  timing "start-to-login" "$START"
}

# api METHOD PATH [curl args...]: a call as the admin, with the ticket. Prints
# the body; fails on anything but HTTP 200, with the body on stderr.
api() {
  local method="$1" path="$2" out code
  shift 2
  out="$(mktemp)"
  code="$(curl -s -o "$out" -w '%{http_code}' -X "$method" \
    -b "PBSAuthCookie=${TICKET}" -H "CSRFPreventionToken: ${CSRF}" \
    "$@" "$(api_url "$path")")" || true
  if [[ "$code" != "200" ]]; then
    log "$method $path answered HTTP ${code:-000}: $(cat "$out")"
    rm -f "$out"
    return 1
  fi
  cat "$out"
  rm -f "$out"
}

# wait_task UPID: waits for a worker task and fails unless it ends with OK.
wait_task() {
  local upid="$1" enc deadline status exitstatus
  enc="$(jq -rn --arg u "$upid" '$u|@uri')"
  deadline=$(($(date +%s) + WAIT_SECONDS))
  while :; do
    status="$(api GET "/nodes/localhost/tasks/${enc}/status")"
    if [[ "$(jq -r '.data.status' <<<"$status")" == "stopped" ]]; then
      exitstatus="$(jq -r '.data.exitstatus' <<<"$status")"
      if [[ "$exitstatus" != "OK" ]]; then
        log "task $upid ended with: $exitstatus"
        return 1
      fi
      return 0
    fi
    if [[ "$(date +%s)" -ge "$deadline" ]]; then
      log "task $upid did not finish in ${WAIT_SECONDS}s"
      return 1
    fi
    sleep 1
  done
}

setup() {
  local t body upid token_secret
  t="$(date +%s)"

  # PBS creates the datastore directory and its chunk store in a worker task
  # when the answer is a UPID.
  body="$(api POST /config/datastore \
    --data-urlencode "name=${DATASTORE}" \
    --data-urlencode "path=${DATASTORE_DIR}/${DATASTORE}" \
    --data-urlencode "comment=terraform-provider-pbs acceptance tests")"
  upid="$(jq -r 'if (.data|type) == "string" then .data else empty end' <<<"$body")"
  if [[ -n "$upid" ]]; then
    wait_task "$upid"
  fi
  timing "datastore" "$t"

  api POST /access/users \
    --data-urlencode "userid=${TEST_USER}" \
    --data-urlencode "password=${TEST_PASS}" \
    --data-urlencode "comment=terraform-provider-pbs acceptance tests" >/dev/null
  api PUT /access/acl --data-urlencode "path=/" --data-urlencode "role=Admin" \
    --data-urlencode "auth-id=${TEST_USER}" >/dev/null

  body="$(api POST "/access/users/${TEST_USER}/token/${TEST_TOKEN_NAME}" \
    --data-urlencode "comment=terraform-provider-pbs acceptance tests")"
  TOKEN_ID="$(jq -r '.data.tokenid' <<<"$body")"
  token_secret="$(jq -r '.data.value' <<<"$body")"
  if [[ -z "$TOKEN_ID" || "$TOKEN_ID" == "null" || -z "$token_secret" || "$token_secret" == "null" ]]; then
    log "the token was created, but the answer has no tokenid or value"
    exit 1
  fi
  API_TOKEN="${TOKEN_ID}:${token_secret}"
  api PUT /access/acl --data-urlencode "path=/" --data-urlencode "role=Admin" \
    --data-urlencode "auth-id=${TOKEN_ID}" >/dev/null
  timing "setup" "$t"
}

# setup_removable_device makes the file system for removable datastores in
# the packages stand: an ext4 image on a loop device, linked from
# /dev/disk/by-uuid, and prints its UUID. A datastore's chunk store has 65536
# directories, so the file system has 1 KiB blocks and inodes enough for two
# of them in 256 MiB; the image is sparse. The loop device is noted for
# release_removable_device.
setup_removable_device() {
  docker exec -i "$CONTAINER" bash -s -- "$REMOVABLE_IMAGE" "$REMOVABLE_LOOP_FILE" <<'SCRIPT'
set -euo pipefail
image="$1" loop_file="$2"
uuid="$(cat /proc/sys/kernel/random/uuid)"
truncate -s 256M "$image"
mkfs.ext4 -q -F -b 1024 -N 140000 -U "$uuid" -L tfacc-removable "$image" >&2
dev=""
for _ in 1 2 3; do
  candidate="$(losetup --find)"
  if [[ ! -b "$candidate" ]]; then
    mknod -m 0660 "$candidate" b 7 "${candidate#/dev/loop}"
  fi
  if losetup "$candidate" "$image" >&2; then
    dev="$candidate"
    break
  fi
done
if [[ -z "$dev" ]]; then
  echo "found no loop device for $image" >&2
  exit 1
fi
echo "$dev" >"$loop_file"
mkdir -p /dev/disk/by-uuid
ln -sfn "$dev" "/dev/disk/by-uuid/$uuid"
echo "$uuid"
SCRIPT
}

# pebble_files writes, to dir, Pebble's configuration and the certificate it
# serves its directory with, for localhost and 127.0.0.1, signed by a CA of
# its own, which PBS is to trust: the certificate in the Pebble image expires
# in October 2027. Nothing reaches stdout, which is evaluated.
pebble_files() {
  local dir="$1"
  mkdir -p "$dir"
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.key" >&2
  openssl req -x509 -new -key "$dir/ca.key" -sha256 -days 30 -subj "/CN=terraform-provider-pbs test CA" \
    -config <(printf '[req]\ndistinguished_name = dn\nx509_extensions = ca\n[dn]\n[ca]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n') \
    -out "$dir/ca.pem" >&2
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/key.pem" >&2
  openssl req -new -key "$dir/key.pem" -subj "/CN=localhost" \
    -config <(printf '[req]\ndistinguished_name = dn\n[dn]\n') -out "$dir/cert.csr" >&2
  openssl x509 -req -in "$dir/cert.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" -set_serial "0x$(rand_hex)" \
    -sha256 -days 30 -out "$dir/cert.pem" \
    -extfile <(printf 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost, IP:127.0.0.1\nauthorityKeyIdentifier = keyid\n') >&2
  # Pebble's own test configuration, with the certificate above and one
  # profile, so that every order gets a 90-day certificate.
  cat >"$dir/pebble-config.json" <<'JSON'
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "/cfg/cert.pem",
    "privateKey": "/cfg/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": { "authz": 3, "order": 5 },
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": { "description": "90-day certificates", "validityPeriod": 7776000 }
    }
  }
}
JSON
}

# start_pebble starts Pebble in the PBS container's network namespace, has
# PBS trust the CA of Pebble's certificate, and waits until PBS reads the
# directory: GET /config/acme/tos makes PBS fetch it.
start_pebble() {
  local t deadline dir body
  t="$(date +%s)"
  dir="${STATE_DIR}/pebble"
  pebble_files "$dir"
  docker image inspect "$PEBBLE_IMAGE" >/dev/null 2>&1 || docker pull -q "$PEBBLE_IMAGE" >&2
  # The files are copied in rather than mounted, so that this works with any
  # Docker daemon, whatever host paths it sees.
  docker create \
    --name "$PEBBLE_CONTAINER" \
    --network "container:${CONTAINER}" \
    -e PEBBLE_VA_ALWAYS_VALID=1 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=0 \
    "$PEBBLE_IMAGE" -config /cfg/pebble-config.json >/dev/null
  docker cp "${dir}/." "${PEBBLE_CONTAINER}:/cfg" >&2
  docker start "$PEBBLE_CONTAINER" >/dev/null

  docker exec "$CONTAINER" mkdir -p /usr/local/share/ca-certificates
  docker cp "${dir}/ca.pem" "${CONTAINER}:/usr/local/share/ca-certificates/terraform-provider-pbs-test.crt" >&2
  docker exec "$CONTAINER" sh -c '
    if command -v update-ca-certificates >/dev/null 2>&1; then
      update-ca-certificates >/dev/null
    else
      mkdir -p /etc/ssl/certs
      cat /usr/local/share/ca-certificates/terraform-provider-pbs-test.crt >>/etc/ssl/certs/ca-certificates.crt
    fi' >&2

  deadline=$(($(date +%s) + WAIT_SECONDS))
  while :; do
    body="$(api GET "/config/acme/tos?directory=$(jq -rn --arg d "$ACME_DIRECTORY" '$d|@uri')" 2>/dev/null)" || true
    if [[ "$(jq -r '.data // empty' <<<"$body" 2>/dev/null)" == data:* ]]; then
      break
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$PEBBLE_CONTAINER" 2>/dev/null || echo false)" != "true" ]]; then
      log "$PEBBLE_CONTAINER stopped"
      dump_logs
      exit 1
    fi
    check_deadline "$deadline" "PBS could not read the ACME directory $ACME_DIRECTORY"
    sleep 1
  done
  timing "pebble" "$t"
}

# s3_files writes, to dir, the S3 server's key and its self-signed
# certificate, for 127.0.0.1 only, in the names MinIO looks for: any other
# name, such as localhost, is then a mismatch the fingerprint overrides. It
# is deliberately not signed by the CA PBS trusts for Pebble: PBS compares
# the fingerprint only when OpenSSL rejects the certificate, so a trusted one
# would let any fingerprint pass. Nothing reaches stdout, which is evaluated.
s3_files() {
  local dir="$1"
  mkdir -p "$dir"
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/private.key" >&2
  openssl req -x509 -new -key "$dir/private.key" -sha256 -days 30 -set_serial "0x$(rand_hex)" \
    -subj "/CN=terraform-provider-pbs test S3" \
    -config <(printf '[req]\ndistinguished_name = dn\nx509_extensions = ext\n[dn]\n[ext]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = IP:127.0.0.1\nsubjectKeyIdentifier = hash\n') \
    -out "$dir/public.crt" >&2
}

# s3_mc runs mc in the S3 container. --insecure: mc only sets the stand up;
# pinning the certificate is PBS's job.
s3_mc() { docker exec "$S3_CONTAINER" mc --insecure --no-color --quiet "$@"; }

# start_s3 starts the S3 server in the PBS container's network namespace,
# makes the buckets once the server answers, and has PBS use it once.
start_s3() {
  local t deadline dir
  t="$(date +%s)"
  dir="${STATE_DIR}/s3"
  (umask 077 && s3_files "$dir")
  S3_FINGERPRINT="$(openssl x509 -noout -fingerprint -sha256 -in "$dir/public.crt" | sed 's/^.*=//')"
  docker image inspect "$S3_IMAGE" >/dev/null 2>&1 || docker pull -q "$S3_IMAGE" >&2
  # The root credentials are the stand's only S3 account. No region is set,
  # so the server accepts whatever region a request is signed for. The
  # files are copied in rather than mounted, as for Pebble. The image's
  # entrypoint runs "server ..." as the server binary's subcommand.
  docker create \
    --name "$S3_CONTAINER" \
    --network "container:${CONTAINER}" \
    -e MINIO_ROOT_USER="$S3_ACCESS_KEY" \
    -e MINIO_ROOT_PASSWORD="$S3_SECRET_KEY" \
    -e MINIO_BROWSER=off \
    "$S3_IMAGE" server --address ":${S3_PORT}" --certs-dir /certs /data >/dev/null
  docker cp "${dir}/." "${S3_CONTAINER}:/certs" >&2
  docker start "$S3_CONTAINER" >/dev/null

  # Ready means the buckets exist: mc fails until the server answers over
  # TLS with the root keys. The secret comes from the container's own
  # environment, so it never shows in a process list on this host.
  deadline=$(($(date +%s) + WAIT_SECONDS))
  while :; do
    # shellcheck disable=SC2016 # expanded by the container's shell
    if docker exec "$S3_CONTAINER" sh -c \
      'mc --insecure --no-color --quiet alias set "$1" "$2" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" --api S3v4' \
      sh "$S3_MC_ALIAS" "https://127.0.0.1:${S3_PORT}" >/dev/null 2>&1 &&
      s3_mc mb --ignore-existing "${S3_BUCKETS[@]/#/${S3_MC_ALIAS}/}" >/dev/null 2>&1; then
      break
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$S3_CONTAINER" 2>/dev/null || echo false)" != "true" ]]; then
      log "$S3_CONTAINER stopped"
      dump_logs
      exit 1
    fi
    check_deadline "$deadline" "the S3 server did not make the buckets"
    sleep 1
  done
  probe_s3
  timing "s3" "$t"
}

# s3_supported tells whether this PBS lists the buckets of an S3 endpoint,
# which probe_s3 and the tests need: PBS 4.0.8 added that, and the check
# without a store prefix probe_s3 runs, to the S3 endpoints of 4.0.4. For an
# endpoint PBS does not have, GET /config/s3/<id>/list-buckets answers 400
# "config lookup failed", and an older PBS 404 "Path '...' not found.". Any
# other answer is a fault of the stand, not a missing feature, and ends the
# script rather than leave the S3 tests to skip unnoticed.
s3_supported() {
  local out code route="/config/s3/tfacc-s3-absent/list-buckets"
  out="$(mktemp)"
  code="$(curl -s -o "$out" -w '%{http_code}' \
    -b "PBSAuthCookie=${TICKET}" "$(api_url "$route")")" || true
  case "${code:-000}" in
    400)
      if grep -q 'config lookup failed' "$out"; then
        rm -f "$out"
        return 0
      fi
      ;;
    404)
      if grep -q "Path '[^']*' not found" "$out"; then
        rm -f "$out"
        return 1
      fi
      ;;
  esac
  log "GET $route answered HTTP ${code:-000}: $(cat "$out")"
  rm -f "$out"
  dump_logs
  exit 1
}

# probe_s3 has PBS use the S3 server once, the way the tests will: an
# endpoint with the pinned fingerprint and path-style requests, its bucket
# list, and PBS's own sanity check (HeadBucket, PutObject, GetObject,
# DeleteObject). The endpoint is removed again, so that the tests start
# without one.
probe_s3() {
  local body name
  if ! api POST /config/s3 \
    --data-urlencode "id=${S3_PROBE_ID}" \
    --data-urlencode "endpoint=${S3_ENDPOINT}" \
    --data-urlencode "port=${S3_PORT}" \
    --data-urlencode "region=${S3_REGION}" \
    --data-urlencode "path-style=true" \
    --data-urlencode "fingerprint=${S3_FINGERPRINT}" \
    --data-urlencode "access-key=${S3_ACCESS_KEY}" \
    --data-urlencode "secret-key=${S3_SECRET_KEY}" >/dev/null; then
    dump_logs
    exit 1
  fi
  if ! body="$(api GET "/config/s3/${S3_PROBE_ID}/list-buckets")" ||
    ! api PUT "/admin/s3/${S3_PROBE_ID}/check" --data-urlencode "bucket=${S3_BUCKETS[0]}" >/dev/null; then
    api DELETE "/config/s3/${S3_PROBE_ID}" >/dev/null || true
    # PBS answers only "failed to list buckets"; the cause is in its log.
    log "PBS could not use the S3 server at https://${S3_ENDPOINT}:${S3_PORT} with fingerprint ${S3_FINGERPRINT}"
    dump_logs
    exit 1
  fi
  api DELETE "/config/s3/${S3_PROBE_ID}" >/dev/null
  for name in "${S3_BUCKETS[@]}"; do
    if ! jq -e --arg n "$name" 'any(.data[]; .name == $n)' <<<"$body" >/dev/null; then
      log "PBS lists the buckets $(jq -c '[.data[].name]' <<<"$body"), without $name"
      exit 1
    fi
  done
}

# ldap_dockerfile prints the Dockerfile of the LDAP server's image: Debian's
# slapd and ldap-utils, with debconf told to leave slapd unconfigured, and a
# policy-rc.d that keeps the package from starting it during the build. The
# configuration below loads back_mdb from /usr/lib/ldap, so the build fails
# when it is not there.
ldap_dockerfile() {
  cat <<EOF
FROM ${LDAP_BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d \\
 && chmod +x /usr/sbin/policy-rc.d \\
 && echo 'slapd slapd/no_configuration boolean true' | debconf-set-selections \\
 && apt-get update \\
 && apt-get install -y --no-install-recommends slapd ldap-utils \\
 && apt-get clean \\
 && rm -rf /var/lib/apt/lists/* \\
 && test -e /usr/lib/ldap/back_mdb.so
EOF
}

# build_ldap_image builds the LDAP server's image unless it exists, and sets
# LDAP_IMAGE. The tag carries a checksum of the Dockerfile, so that changing
# it builds a new image.
build_ldap_image() {
  local ctx base sum
  base="$(printf '%s' "${LDAP_BASE_IMAGE##*/}" | tr -c 'A-Za-z0-9_.-' '-')"
  sum="$(ldap_dockerfile | cksum | cut -d' ' -f1)"
  LDAP_IMAGE="pbs-tfprovider-test-ldap:${base}-${sum}"
  if docker image inspect "$LDAP_IMAGE" >/dev/null 2>&1; then
    log "reusing image $LDAP_IMAGE"
    return 0
  fi
  ctx="$(mktemp -d)"
  ldap_dockerfile >"$ctx/Dockerfile"
  log "building $LDAP_IMAGE from $LDAP_BASE_IMAGE"
  docker build --progress=plain -t "$LDAP_IMAGE" "$ctx" >&2
  rm -rf "$ctx"
}

# ldap_files writes, to dir, a throwaway CA, and, to dir/slapd, what slapd
# needs: its configuration; a schema with the Active Directory attributes,
# sAMAccountName and defaultNamingContext, and an auxiliary class for the
# former; the root DSE's defaultNamingContext; the directory's entries; and
# a certificate for localhost and 127.0.0.1, signed by the CA, with its key
# and the CA's certificate. The passwords are random and in plain text, which
# slapd compares as it is; the files are for this owner only. Nothing
# reaches stdout, which is evaluated.
ldap_files() {
  local dir="$1" rootpw dc
  rootpw="root-$(rand_hex)"
  dc="${LDAP_BASE_DN%%,*}"
  dc="${dc#dc=}"
  (
    umask 077
    mkdir -p "$dir/slapd"
    openssl genrsa -out "$dir/ca.key" 2048 >&2
    openssl req -x509 -new -key "$dir/ca.key" -sha256 -days 30 -subj "/CN=terraform-provider-pbs test LDAP CA" \
      -config <(printf '[req]\ndistinguished_name = dn\nx509_extensions = ca\n[dn]\n[ca]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n') \
      -out "$dir/ca.pem" >&2
    openssl genrsa -out "$dir/slapd/key.pem" 2048 >&2
    openssl req -new -key "$dir/slapd/key.pem" -subj "/CN=localhost" \
      -config <(printf '[req]\ndistinguished_name = dn\n[dn]\n') -out "$dir/cert.csr" >&2
    openssl x509 -req -in "$dir/cert.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" -set_serial "0x$(rand_hex)" \
      -sha256 -days 30 -out "$dir/slapd/cert.pem" \
      -extfile <(printf 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost, IP:127.0.0.1\nauthorityKeyIdentifier = keyid\n') >&2
    cp "$dir/ca.pem" "$dir/slapd/ca.pem"

    # Anyone reads the root DSE, where PBS asks for defaultNamingContext
    # anonymously, and the schema. Everything else needs a bind, and a
    # password serves only to bind.
    cat >"$dir/slapd/slapd.conf" <<EOF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include /etc/ldap/schema/nis.schema
include ${LDAP_CONFIG_DIR}/ad.schema

modulepath /usr/lib/ldap
moduleload back_mdb

rootDSE ${LDAP_CONFIG_DIR}/rootdse.ldif

TLSCACertificateFile ${LDAP_CONFIG_DIR}/ca.pem
TLSCertificateFile ${LDAP_CONFIG_DIR}/cert.pem
TLSCertificateKeyFile ${LDAP_CONFIG_DIR}/key.pem

access to dn.base="" by * read
access to dn.base="cn=Subschema" by * read
access to attrs=userPassword
  by self write
  by anonymous auth
  by * none
access to *
  by users read
  by anonymous auth
  by * none

database mdb
suffix "${LDAP_BASE_DN}"
rootdn "cn=admin,${LDAP_BASE_DN}"
rootpw ${rootpw}
directory /var/lib/tfacc-ldap
index objectClass eq
index uid,sAMAccountName eq
EOF

    # OIDs: Microsoft's for sAMAccountName, and below 1.3.6.1.4.1.32473,
    # IANA's arc for examples, for the rest.
    cat >"$dir/slapd/ad.schema" <<'EOF'
attributetype ( 1.2.840.113556.1.4.221 NAME 'sAMAccountName'
  DESC 'Active Directory: the name an account signs in with'
  EQUALITY caseIgnoreMatch
  SUBSTR caseIgnoreSubstringsMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE )

attributetype ( 1.3.6.1.4.1.32473.1.1.1 NAME 'defaultNamingContext'
  DESC 'Active Directory root DSE: the root of the domain'
  EQUALITY distinguishedNameMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
  SINGLE-VALUE )

objectclass ( 1.3.6.1.4.1.32473.1.2.1 NAME 'tfaccADAccount'
  DESC 'An entry Active Directory realms find by sAMAccountName'
  SUP top AUXILIARY
  MAY sAMAccountName )
EOF

    printf 'dn:\ndefaultNamingContext: %s\n' "$LDAP_BASE_DN" >"$dir/slapd/rootdse.ldif"

    cat >"$dir/slapd/seed.ldif" <<EOF
dn: ${LDAP_BASE_DN}
objectClass: dcObject
objectClass: organization
dc: ${dc}
o: terraform-provider-pbs acceptance tests

dn: ou=people,${LDAP_BASE_DN}
objectClass: organizationalUnit
ou: people

dn: ou=services,${LDAP_BASE_DN}
objectClass: organizationalUnit
ou: services

dn: ${LDAP_BIND_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: pbs-bind
description: The account PBS binds as to look users up
userPassword: ${LDAP_BIND_PASS}

dn: ${LDAP_USER_DN}
objectClass: inetOrgPerson
objectClass: tfaccADAccount
uid: ${LDAP_USER}
sAMAccountName: ${LDAP_USER}
cn: Alice Example
givenName: Alice
sn: Example
mail: ${LDAP_USER}@example.org
userPassword: ${LDAP_USER_PASS}
EOF
  )
}

# check_ldap checks, from the LDAP container, what the tests rely on: the
# root DSE names the base DN as defaultNamingContext to anonymous clients,
# which read nothing else; the bind account finds the user by uid and by
# sAMAccountName; LDAPS and StartTLS work with the certificate verified
# against the CA, for the address PBS connects to; and the user binds with
# its password.
check_ldap() {
  docker exec -i "$LDAP_CONTAINER" bash -s -- "${LDAP_CONFIG_DIR}/ca.pem" "$LDAP_SERVER" "$LDAP_BASE_DN" \
    "$LDAP_BIND_DN" "$LDAP_BIND_PASS" "$LDAP_USER" "$LDAP_USER_DN" "$LDAP_USER_PASS" >&2 <<'SCRIPT'
set -euo pipefail
ca="$1" server="$2" base="$3" bind_dn="$4" bind_pass="$5" user="$6" user_dn="$7" user_pass="$8"
fail() { echo "the LDAP server is not as the tests expect: $*" >&2; exit 1; }
search() { ldapsearch -x -LLL -o ldif_wrap=no -o nettimeout=5 "$@"; }
[[ "$(search -H "ldap://$server:389/" -b "" -s base defaultNamingContext)" == *"defaultNamingContext: $base"* ]] ||
  fail "the root DSE names no defaultNamingContext $base"
if search -H "ldap://$server:389/" -b "$base" -s base dn >/dev/null 2>&1; then
  fail "anonymous clients read $base"
fi
for attr in uid sAMAccountName; do
  [[ "$(search -H "ldap://$server:389/" -D "$bind_dn" -w "$bind_pass" -b "$base" "($attr=$user)" dn)" == "dn: $user_dn" ]] ||
    fail "$bind_dn does not find $user_dn by $attr"
done
export LDAPTLS_CACERT="$ca" LDAPTLS_REQCERT=demand
search -H "ldaps://$server:636/" -D "$bind_dn" -w "$bind_pass" -b "$base" -s base dn >/dev/null ||
  fail "LDAPS, verifying the certificate, failed"
search -ZZ -H "ldap://$server:389/" -D "$bind_dn" -w "$bind_pass" -b "$base" -s base dn >/dev/null ||
  fail "StartTLS, verifying the certificate, failed"
ldapwhoami -x -o nettimeout=5 -H "ldap://$server:389/" -D "$user_dn" -w "$user_pass" >/dev/null ||
  fail "$user_dn cannot bind with its password"
SCRIPT
}

# start_ldap starts slapd in the PBS container's network namespace, puts the
# CA's certificate into the PBS container, at LDAP_CA_FILE, and waits until
# the bind account reads the directory. slapd logs every operation, with its
# result, for dump_logs and the CI's logs.
start_ldap() {
  local t dir deadline
  t="$(date +%s)"
  build_ldap_image
  timing "ldap-build" "$t"
  LDAP_BIND_PASS="bind-$(rand_hex)"
  LDAP_USER_PASS="${LDAP_USER}-$(rand_hex)"
  dir="${STATE_DIR}/ldap"
  ldap_files "$dir"
  # The files are copied in, as Pebble's are; slapadd loads the directory
  # before slapd starts.
  # shellcheck disable=SC2016 # expanded by the container's shell
  docker create \
    --name "$LDAP_CONTAINER" \
    --network "container:${CONTAINER}" \
    "$LDAP_IMAGE" \
    sh -c 'mkdir -p /var/lib/tfacc-ldap && slapadd -q -f "$1/slapd.conf" -l "$1/seed.ldif" && exec slapd -d stats -f "$1/slapd.conf" -h "$2"' \
    sh "$LDAP_CONFIG_DIR" "ldap://${LDAP_SERVER}:389/ ldaps://${LDAP_SERVER}:636/" >/dev/null
  docker cp "${dir}/slapd/." "${LDAP_CONTAINER}:${LDAP_CONFIG_DIR}" >&2
  docker start "$LDAP_CONTAINER" >/dev/null

  docker exec "$CONTAINER" mkdir -p "${LDAP_CA_FILE%/*}"
  docker cp "${dir}/ca.pem" "${CONTAINER}:${LDAP_CA_FILE}" >&2
  docker exec "$CONTAINER" chmod 0644 "$LDAP_CA_FILE"

  deadline=$(($(date +%s) + WAIT_SECONDS))
  until docker exec "$LDAP_CONTAINER" ldapsearch -x -LLL -o nettimeout=2 -H "ldap://${LDAP_SERVER}:389/" \
    -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" -b "$LDAP_BASE_DN" -s base dn >/dev/null 2>&1; do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$LDAP_CONTAINER" 2>/dev/null || echo false)" != "true" ]]; then
      log "$LDAP_CONTAINER stopped"
      dump_logs
      exit 1
    fi
    if [[ "$(date +%s)" -ge "$deadline" ]]; then
      log "$LDAP_BIND_DN could not read $LDAP_BASE_DN within ${WAIT_SECONDS}s"
      dump_logs
      exit 1
    fi
    sleep 1
  done
  if ! check_ldap; then
    dump_logs
    exit 1
  fi
  timing "ldap" "$t"
}

# print_ldap_exports prints the facts about the LDAP server, or, when there
# is none, unsets what an earlier run exported in the same shell.
print_ldap_exports() {
  local name
  if [[ "$LDAP" == "0" ]]; then
    for name in SERVER BASE_DN BIND_DN BIND_PASSWORD USER USER_PASSWORD CA_FILE; do
      printf 'unset PBS_ACC_LDAP_%s\n' "$name"
    done
    return 0
  fi
  printf 'export PBS_ACC_LDAP_SERVER=%q\n' "$LDAP_SERVER"
  printf 'export PBS_ACC_LDAP_BASE_DN=%q\n' "$LDAP_BASE_DN"
  printf 'export PBS_ACC_LDAP_BIND_DN=%q\n' "$LDAP_BIND_DN"
  printf 'export PBS_ACC_LDAP_BIND_PASSWORD=%q\n' "$LDAP_BIND_PASS"
  printf 'export PBS_ACC_LDAP_USER=%q\n' "$LDAP_USER"
  printf 'export PBS_ACC_LDAP_USER_PASSWORD=%q\n' "$LDAP_USER_PASS"
  printf 'export PBS_ACC_LDAP_CA_FILE=%q\n' "$LDAP_CA_FILE"
}

# save_certificate keeps PBS's own certificate and key, which the
# certificate tests put back, so that PBS_TLS_FINGERPRINT holds again. The
# key is written through the shell, so that it gets the umask's mode.
save_certificate() {
  (
    umask 077
    mkdir -p "$STATE_DIR"
    docker exec "$CONTAINER" cat /etc/proxmox-backup/proxy.pem >"${STATE_DIR}/proxy.pem"
    docker exec "$CONTAINER" cat /etc/proxmox-backup/proxy.key >"${STATE_DIR}/proxy.key"
  )
}

# fingerprint prints the SHA-256 fingerprint of proxy.pem as PBS reports it,
# after checking it against the certificate the port serves.
fingerprint() {
  local fp served
  fp="$(api GET /nodes/localhost/certificates/info |
    jq -r '.data[] | select(.filename == "proxy.pem") | .fingerprint')"
  if [[ -z "$fp" || "$fp" == "null" ]]; then
    log "GET /nodes/localhost/certificates/info has no proxy.pem fingerprint"
    exit 1
  fi
  if command -v openssl >/dev/null 2>&1; then
    served="$(timeout 10 openssl s_client -connect "127.0.0.1:${PORT}" </dev/null 2>/dev/null |
      openssl x509 -noout -fingerprint -sha256 | sed 's/^.*=//')"
    if [[ "$(tr 'a-f' 'A-F' <<<"$served")" != "$(tr 'a-f' 'A-F' <<<"$fp")" ]]; then
      log "fingerprint mismatch: PBS reports $fp, the port serves $served"
      exit 1
    fi
  fi
  echo "$fp"
}

# check_token makes sure the exported token works before anyone relies on it.
check_token() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: PBSAPIToken=${API_TOKEN}" "$(api_url /access/permissions)")" || true
  if [[ "$code" != "200" ]]; then
    log "GET /access/permissions with the new token answered HTTP ${code:-000}"
    exit 1
  fi
}

save_state() {
  (
    umask 077
    mkdir -p "$STATE_DIR"
    {
      printf 'VARIANT=%q\nIMAGE=%q\nPORT=%q\n' "$VARIANT" "$IMAGE" "$PORT"
      printf 'ADMIN_USER=%q\nADMIN_PASS=%q\n' "$ADMIN_USER" "$ADMIN_PASS"
      printf 'TEST_PASS=%q\nAPI_TOKEN=%q\n' "$TEST_PASS" "${API_TOKEN:-}"
      printf 'S3_ACCESS_KEY=%q\nS3_SECRET_KEY=%q\n' "$S3_ACCESS_KEY" "$S3_SECRET_KEY"
    } >"${STATE_DIR}/env"
  )
}

print_exports() {
  printf 'export PBS_ENDPOINT=%q\n' "$(base_url)"
  printf 'export PBS_API_TOKEN=%q\n' "$API_TOKEN"
  printf 'export PBS_TLS_FINGERPRINT=%q\n' "$1"
  printf 'export PBS_ACC_USERNAME=%q\n' "$TEST_USER"
  printf 'export PBS_ACC_PASSWORD=%q\n' "$TEST_PASS"
  printf 'export PBS_ACC_ADMIN_USERNAME=%q\n' "$ADMIN_USER"
  printf 'export PBS_ACC_ADMIN_PASSWORD=%q\n' "$ADMIN_PASS"
  printf 'export PBS_ACC_DATASTORE=%q\n' "$DATASTORE"
  printf 'export PBS_ACC_DATASTORE_DIR=%q\n' "$DATASTORE_DIR"
  printf 'export PBS_ACC_CONTAINER=%q\n' "$CONTAINER"
  printf 'export PBS_ACC_VARIANT=%q\n' "$VARIANT"
  printf 'export PBS_ACC_VERSION=%q\n' "$2"
  printf 'export PBS_ACC_PROXY_CERT_FILE=%q\n' "${STATE_DIR}/proxy.pem"
  printf 'export PBS_ACC_PROXY_KEY_FILE=%q\n' "${STATE_DIR}/proxy.key"
  # Both stands map host.docker.internal to this host (--add-host), under
  # native Docker and Docker Desktop alike.
  printf 'export PBS_ACC_HOST_ADDRESS=%q\n' "host.docker.internal"
  if [[ "$PEBBLE" != "0" ]]; then
    printf 'export PBS_ACC_ACME_DIRECTORY=%q\n' "$ACME_DIRECTORY"
  else
    # Clear what an earlier run exported in the same shell.
    printf 'unset PBS_ACC_ACME_DIRECTORY\n'
  fi
  if [[ "$S3" != "0" ]]; then
    printf 'export PBS_ACC_S3_CONTAINER=%q\n' "$S3_CONTAINER"
    printf 'export PBS_ACC_S3_ENDPOINT=%q\n' "$S3_ENDPOINT"
    printf 'export PBS_ACC_S3_PORT=%q\n' "$S3_PORT"
    printf 'export PBS_ACC_S3_REGION=%q\n' "$S3_REGION"
    printf 'export PBS_ACC_S3_ACCESS_KEY=%q\n' "$S3_ACCESS_KEY"
    printf 'export PBS_ACC_S3_SECRET_KEY=%q\n' "$S3_SECRET_KEY"
    printf 'export PBS_ACC_S3_FINGERPRINT=%q\n' "$S3_FINGERPRINT"
    printf 'export PBS_ACC_S3_BUCKET=%q\n' "${S3_BUCKETS[0]}"
    printf 'export PBS_ACC_S3_BUCKETS=%q\n' "$(IFS=,; echo "${S3_BUCKETS[*]}")"
    printf 'export PBS_ACC_S3_MC_ALIAS=%q\n' "$S3_MC_ALIAS"
  else
    printf 'unset PBS_ACC_S3_CONTAINER PBS_ACC_S3_ENDPOINT PBS_ACC_S3_PORT PBS_ACC_S3_REGION PBS_ACC_S3_ACCESS_KEY PBS_ACC_S3_SECRET_KEY PBS_ACC_S3_FINGERPRINT PBS_ACC_S3_BUCKET PBS_ACC_S3_BUCKETS PBS_ACC_S3_MC_ALIAS\n'
  fi
  if [[ -n "$REMOVABLE_UUID" ]]; then
    printf 'export PBS_ACC_REMOVABLE_UUID=%q\n' "$REMOVABLE_UUID"
  else
    printf 'unset PBS_ACC_REMOVABLE_UUID\n'
  fi
  print_ldap_exports
}

# Always a fresh server, so that every test run starts from the same state.
docker rm -f -v "$PEBBLE_CONTAINER" >/dev/null 2>&1 || true
docker rm -f -v "$S3_CONTAINER" >/dev/null 2>&1 || true
docker rm -f -v "$LDAP_CONTAINER" >/dev/null 2>&1 || true
release_removable_device
docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
docker volume rm -f "${VOLUMES[@]}" >/dev/null 2>&1 || true
rm -rf "$STATE_DIR"

t="$(date +%s)"
if [[ "$VARIANT" == "image" ]]; then
  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >&2
  timing "pull" "$t"
  START="$(date +%s)"
  start_image
else
  build_packages_image
  timing "build" "$t"
  START="$(date +%s)"
  start_packages
  # chpasswd needs the container, not systemd; PAM reads /etc/shadow at login.
  printf 'root:%s\n' "$ADMIN_PASS" | docker exec -i "$CONTAINER" chpasswd
  # Keep the resolver Docker wrote, but as a plain file PBS can replace.
  docker exec "$CONTAINER" sh -c 'cp /etc/resolv.conf /tmp/resolv.conf && umount /etc/resolv.conf && cp /tmp/resolv.conf /etc/resolv.conf'
fi
save_state

wait_ready
setup
save_state
check_token
if [[ "$PEBBLE" != "0" ]]; then
  start_pebble
fi
if [[ "$S3" != "0" ]]; then
  if s3_supported; then
    start_s3
  else
    log "this PBS cannot list the buckets of an S3 endpoint (PBS 4.0.8 added that); starting no S3 server"
    S3=0
  fi
fi
if [[ "$LDAP" != "0" ]]; then
  start_ldap
fi
if [[ "$VARIANT" == "packages" && "$REMOVABLE" != "0" ]]; then
  t="$(date +%s)"
  REMOVABLE_UUID="$(setup_removable_device)"
  timing "removable" "$t"
fi
save_certificate
FINGERPRINT="$(fingerprint)"
VERSION="$(api GET /version | jq -r '.data | "\(.version).\(.release)"')"
log "PBS $VERSION ($VARIANT) is ready at $(base_url) with datastore $DATASTORE"
timing "total" "$T0"
print_exports "$FINGERPRINT" "$VERSION"
