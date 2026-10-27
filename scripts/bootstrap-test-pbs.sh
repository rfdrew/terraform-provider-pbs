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
# then prints what the provider reads — PBS_ENDPOINT, PBS_API_TOKEN and
# PBS_TLS_FINGERPRINT — and the PBS_ACC_* facts the tests need: the test
# user's password, the admin account, the datastore, the container, the
# variant and the PBS version. The test user's credentials are not exported
# as PBS_USERNAME and PBS_PASSWORD, which the provider would read alongside
# the token.
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

if [[ "${1:-}" == "--teardown" ]]; then
  docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm -f "${VOLUMES[@]}" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
  log "removed $CONTAINER, its volumes and $STATE_DIR"
  exit 0
fi

trap 'status=$?; if [[ $status -ne 0 ]]; then echo false; fi' EXIT

command -v docker >/dev/null || { log "docker not found"; exit 1; }
command -v jq >/dev/null || { log "jq not found"; exit 1; }

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

container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)" == "true" ]]
}

dump_logs() {
  log "--- docker logs $CONTAINER (tail)"
  docker logs --tail 100 "$CONTAINER" >&2 2>&1 || true
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
  # proxmox-backup-client comes along to write test backups.
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
 && apt-get install -y --no-install-recommends "proxmox-backup-server=\$v" proxmox-backup-client \\
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
  mkdir -p "$STATE_DIR"
  (
    umask 077
    {
      printf 'VARIANT=%q\nIMAGE=%q\nPORT=%q\n' "$VARIANT" "$IMAGE" "$PORT"
      printf 'ADMIN_USER=%q\nADMIN_PASS=%q\n' "$ADMIN_USER" "$ADMIN_PASS"
      printf 'TEST_PASS=%q\nAPI_TOKEN=%q\n' "$TEST_PASS" "${API_TOKEN:-}"
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
}

# Always a fresh server, so that every test run starts from the same state.
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
FINGERPRINT="$(fingerprint)"
VERSION="$(api GET /version | jq -r '.data | "\(.version).\(.release)"')"
log "PBS $VERSION ($VARIANT) is ready at $(base_url) with datastore $DATASTORE"
timing "total" "$T0"
print_exports "$FINGERPRINT" "$VERSION"
