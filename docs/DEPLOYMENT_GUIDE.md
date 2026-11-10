# CISO Executive Dashboard: Deployment Guide

**Audience:** system engineers deploying the dashboard on a new machine. That machine might be a test VM, a production server, a laptop for a demonstration, or a replacement for an existing installation.
**Outcome:** a running, verified installation that users can sign in to, with a record of how it was built.

Day-2 operations are in the [Maintenance Manual](MAINTENANCE_MANUAL.md), and every runtime parameter is in [CONFIGURATION.md](CONFIGURATION.md).

---

## Contents

1. [Choose your scenario](#1-choose-your-scenario)
2. [Decisions to make before you start](#2-decisions-to-make-before-you-start)
3. [Target system requirements](#3-target-system-requirements)
4. [Step 1: prepare the host](#4-step-1-prepare-the-host)
5. [Step 2: get the code](#5-step-2-get-the-code)
6. [Step 3: TLS certificates](#6-step-3-tls-certificates)
7. [Step 4: secrets and deployment profile](#7-step-4-secrets-and-deployment-profile)
8. [Step 5: build and start](#8-step-5-build-and-start)
9. [Step 6: verify](#9-step-6-verify)
10. [Step 7: client access and first sign-in](#10-step-7-client-access-and-first-sign-in)
11. [Step 8: post-deployment hardening](#11-step-8-post-deployment-hardening)
12. [Moving an existing installation to another system](#12-moving-an-existing-installation-to-another-system)
13. [Offline (air-gapped) deployment](#13-offline-air-gapped-deployment)
14. [Deploying behind a load balancer or reverse proxy](#14-deploying-behind-a-load-balancer-or-reverse-proxy)
15. [Ports and firewall summary](#15-ports-and-firewall-summary)
16. [Troubleshooting a first deployment](#16-troubleshooting-a-first-deployment)
17. [Starting over or removing an installation](#17-starting-over-or-removing-an-installation)
18. [Deployment sign-off checklist](#18-deployment-sign-off-checklist)

---

## 1. Choose your scenario

| Scenario | Follow | Typical time |
|----------|--------|--------------|
| **A. Demonstration or evaluation**, with sample data and the demo administrator | Steps 1–7, using the demo profile | 20–30 min |
| **B. New production installation**, with real users and real tools | Steps 1–8, using the production profile | 1–2 h, plus connector onboarding |
| **C. Move an existing installation** to new hardware, keeping data, users and MFA | §12 (uses Steps 1–6) | 1 h, plus data transfer |
| **D. Offline / air-gapped host** | §13, then Steps 3–8 | 1–2 h |
| **E. Behind a load balancer or reverse proxy** | Scenario A or B, plus §14 | +30 min |

---

## 2. Decisions to make before you start

Record these answers. They become the build record for this installation.

| # | Decision | Options | Example |
|---|----------|---------|---------|
| 1 | **Public address** users will type | DNS name (recommended) or fixed IP | `https://ciso.corp.example` or `https://10.20.5.15` |
| 2 | **Alternative names / IPs** that must also work | Extra DNS names, the server IP | `10.20.5.15`, `ciso` |
| 3 | **Profile** | `demo` (sample data, live simulator, demo admin `admin` / `Admin@123!`) or `production` (empty, no demo accounts) | production |
| 4 | **Certificates** | Generated internal CA (fast) or enterprise PKI (recommended for production) | enterprise PKI |
| 5 | **Identity provider** | Bundled Keycloak (default) or corporate OIDC (Entra ID, Okta, Ping) | bundled |
| 6 | **Published ports** | HTTPS 443 and HTTP 80 (redirect), or others if those are taken | 443 / 80 |
| 7 | **Load balancer** in front? | None, or its addresses (§14) | none |
| 8 | **Who operates it** | A named, non-root Linux user in the `docker` group | `cisoops` |
| 9 | **Backups** | Destination and schedule for the encrypted database dumps and key archive | nightly to a backup vault |

---

## 3. Target system requirements

| Item | Requirement |
|------|-------------|
| OS | Ubuntu 22.04 / 24.04 LTS, RHEL / Rocky / AlmaLinux 9 (recommended for servers); Windows 10/11 or macOS with Docker Desktop for demonstrations |
| CPU / RAM / disk | 2 vCPU / 6 GB / 20 GB minimum; **4 vCPU / 8 GB / 40 GB SSD recommended** |
| Container runtime | Docker Engine 24+ with the Compose v2 plugin (`docker compose`), or Podman 4.9+ with `podman compose` |
| Tools | `git`, `bash`, `openssl`, `curl` |
| Time | NTP synchronised. TOTP codes fail when the clock drifts by more than about 30 seconds |
| Internet (build time) | Outbound HTTPS to `registry-1.docker.io`, `quay.io` and `registry.npmjs.org`, unless you use §13 |
| Internet (run time) | Outbound HTTPS to your security tools' APIs and `www.cisa.gov` (threat feed). Nothing inbound except 443/80 |
| Address space | The stack uses **172.30.0.0/16** for its internal Docker networks. If your corporate network uses any part of that range, change it before the first start (§16, *address overlap*) |
| One installation per host | The Compose project name (`ciso-dashboard`) and the internal subnets are fixed, so a Docker host runs **one** installation. A second copy on the same host would share the database volume, and `docker compose down -v` in either copy would delete it. Use a separate VM for test and production |

**What has been verified.** This guide was followed on a fresh clone of the GitHub repository on Docker Desktop (Linux containers), using the demo profile: Steps 2–6 completed and the smoke test passed 63 of 63 checks. The generated host baseline script was dry-run on Ubuntu 24.04 and Rocky Linux 9. Linux servers are the intended production platform. Run the smoke test (Step 6) on every new system, so that you have verified the deployment yourself.

---

## 4. Step 1: prepare the host

### 4.1 Ubuntu 22.04 / 24.04

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git openssl
# Docker Engine + Compose plugin from Docker's official repository
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

### 4.2 RHEL 9 / Rocky / AlmaLinux 9

```bash
sudo dnf install -y git openssl curl dnf-plugins-core
# RHEL: use .../linux/rhel/docker-ce.repo; Rocky and Alma: .../linux/centos/docker-ce.repo
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

With Podman instead, `sudo dnf install -y podman podman-compose` and use `podman compose` wherever this guide says `docker compose`. Bind mounts already carry the `:z` SELinux label.

### 4.3 Operator account (Linux)

Run every script as a **regular user in the `docker` group, never with `sudo`**. `generate-secrets.sh` records that user's UID and GID in `.env`. The containers run as that UID, so they can read the mode-600 secret files the user owns.

```bash
sudo useradd -m -s /bin/bash cisoops          # or use an existing admin account
sudo usermod -aG docker cisoops               # log out and in again for the group to apply
sudo mkdir -p /opt/ciso-dashboard && sudo chown cisoops: /opt/ciso-dashboard
```

Check: `docker run --rm hello-world` works without `sudo`, and `docker compose version` shows v2.

### 4.4 Windows or macOS (demonstration)

1. Install **Docker Desktop** (WSL 2 backend on Windows) and give it at least 6 GB of memory (Settings → Resources).
2. On Windows, install **Git for Windows** and run every command in **Git Bash**.
3. Make sure nothing else listens on ports 443 and 80, such as IIS, Skype or another web server. If something does, choose other ports in Step 4.

### 4.5 Time and DNS

- `timedatectl` should show *System clock synchronized: yes*. If it doesn't, enable chrony or systemd-timesyncd.
- The public name must resolve to this host, both from users' machines and **from the host itself**, because the smoke test calls the public URL. For a test system without DNS, add a hosts entry such as `10.20.5.15 ciso.corp.example`.

---

## 5. Step 2: get the code

```bash
cd /opt/ciso-dashboard            # Windows: any folder without spaces, e.g. C:/ciso-dashboard
git clone https://github.com/subas-007/CISO_DASHBOARD.git .
git log --oneline -1              # record the commit you are deploying
```

- Deploy a **specific commit or tag** for production (`git checkout <tag>`), and record it.
- `.gitattributes` forces LF line endings, so the shell scripts work even when the repository is cloned on Windows.
- The repository contains **no secrets, certificates or `.env`**. You create these on every system in Steps 3 and 4. Never copy them from another installation, except when migrating (§12).

---

## 6. Step 3: TLS certificates

### Option 1: generated internal CA (demonstration, test, or until PKI certificates arrive)

```bash
# public name first; the extra names/IPs from decision 2 in CERT_SANS
CERT_SANS=10.20.5.15 ./scripts/generate-certs.sh ciso.corp.example
# demo on a laptop:
./scripts/generate-certs.sh localhost
```

This creates `certs/ca.crt` and `ca.key` (CA, valid 5 years) and `certs/tls.crt` and `tls.key` (service certificate, valid 397 days). The service certificate covers the public name, the extra names, and the internal service names.

> Keep `certs/ca.key` in a safe place. It is not needed at run time, but `apply-deployment.sh` uses it to re-issue the certificate when you later add names.

### Option 2: enterprise PKI (production)

1. Request a server certificate whose **SANs** include:
   - the public name and every alternative name or IP
   - the internal names `gateway`, `api`, `keycloak`, `postgres` and `localhost`, and the IP `127.0.0.1`

   It also needs **both extended key usages, serverAuth and clientAuth**, because the gateway reuses the same certificate as its client certificate for mutual TLS to the API.
2. Place the files, keeping these exact names:

| File | Content |
|------|---------|
| `certs/tls.crt` | Server certificate followed by the intermediate chain (PEM) |
| `certs/tls.key` | Private key (PEM, unencrypted, mode 600) |
| `certs/ca.crt` | The issuing CA chain (PEM). Internal services use it to trust each other |

3. Run `chmod 600 certs/tls.key && chmod 644 certs/tls.crt certs/ca.crt`.
4. Check the certificate: `openssl x509 -in certs/tls.crt -noout -subject -enddate -ext subjectAltName`.

All services use this one certificate: the gateway, the API, Keycloak and PostgreSQL.

---

## 7. Step 4: secrets and deployment profile

**Production:**
```bash
PUBLIC_BASE_URL=https://ciso.corp.example SEED_DEMO_DATA=false ./scripts/generate-secrets.sh
```

**Demonstration** (sample data, live simulator, demo administrator `admin` / `Admin@123!`):
```bash
PUBLIC_BASE_URL=https://localhost ./scripts/generate-secrets.sh
# optional: choose your own demo admin credentials instead of the published default
DEMO_ADMIN_USERNAME=demoadmin DEMO_ADMIN_PASSWORD='S0me-Long-Passphrase!' PUBLIC_BASE_URL=https://localhost ./scripts/generate-secrets.sh
```

What it creates:
- **`.env`** (mode 600): the public URL, your UID and GID, ports, the profile, database and Keycloak bootstrap passwords, and deployment defaults.
- **`secrets/`** (mode 600): database URLs, JWT, state, data-encryption, blind-index and audit keys, the OIDC client secret, the provisioner secret, the Keycloak admin password and (demo only) the demo admin password.

Every value comes from `openssl rand`. The script **refuses to overwrite** an existing `.env`, or encryption keys that have no `.env`, so it cannot destroy a running installation by accident.

**Optional edits to `.env`** before the first start:

| Key | When to change |
|-----|----------------|
| `HTTPS_PORT`, `HTTP_PORT` | Ports 443 or 80 are taken, for example `HTTPS_PORT=8443`. Then include the port in `PUBLIC_BASE_URL` (`https://ciso.corp.example:8443`) |
| `CERT_SANS` | Must list the same alternative names you put in the certificate |
| `TRUSTED_UPSTREAM_PROXIES` | Behind a load balancer (§14) |
| `API_MEMORY`, `KEYCLOAK_MEMORY`, `POSTGRES_MEMORY` | Larger estates (defaults `1024m`, `1536m`, `2048m`) |
| `APP_UID`, `APP_GID` | **Windows only:** set both to `1000`, because Git Bash reports a Windows SID-based ID that the containers can't use |

**Store the secrets now.** Copy `.env`, `secrets/` and `certs/` to your vault or password manager as an encrypted archive (Maintenance Manual §8.2). Without `secrets/data_encryption_keys` and `secrets/audit_hmac_key`, a restored database cannot be read or verified.

---

## 8. Step 5: build and start

```bash
docker compose up -d --build --wait
```

- **First build takes 3–10 minutes:** it downloads base images and npm packages and compiles the API and the web application. Later starts take under a minute.
- **`--wait` returns only when every service is healthy.** The one-shot `migrate` and `idp-init` jobs must also have completed successfully.
- **Start order:** postgres → keycloak → migrate (database schema) → idp-init (Keycloak client, service account, identity policy, demo admin) → api → gateway.

Check the result:

```bash
docker compose ps        # api, gateway, keycloak, postgres: "Up … (healthy)"
docker compose ps -a     # migrate and idp-init: "Exited (0)"
docker compose logs idp-init | tail -3     # "identity provider bootstrap complete"
```

---

## 9. Step 6: verify

```bash
curl -sk https://ciso.corp.example/api/ready     # {"status":"ready"}
./scripts/smoke-test.sh                          # run on the Docker host
```

The smoke test signs in through the real sign-in flow with temporary users, one per role, and runs **63 checks**:
- role permissions, CSRF and SSRF protection
- token rotation and reuse detection
- audit chain integrity and tamper resistance
- database privileges and TLS
- rate limiting and the configuration endpoints

It deletes its temporary users at the end. **Expected result: `Result: 63 passed, 0 failed`.** Keep the output with your deployment record.

---

## 10. Step 7: client access and first sign-in

### 10.1 Trust the CA (generated certificates only)

Distribute `certs/ca.crt`, the **certificate only, never `ca.key`**, to client machines. For many machines, use Group Policy or MDM.

| Client | Command or action |
|--------|-------------------|
| Windows | `certutil -addstore -f Root ca.crt` (admin), or Group Policy → Trusted Root Certification Authorities |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt` |
| Ubuntu / Debian | `sudo cp ca.crt /usr/local/share/ca-certificates/ciso-ca.crt && sudo update-ca-certificates` |
| RHEL family | `sudo cp ca.crt /etc/pki/ca-trust/source/anchors/ciso-ca.crt && sudo update-ca-trust` |
| Firefox | Settings → Certificates → Import, and tick "trust to identify websites" (Firefox keeps its own store) |

### 10.2 First sign-in

1. Open `https://<public address>/` and select **Sign in**.
2. **Demo profile:** sign in as `admin` / `Admin@123!`.
   **Production profile:** create the first administrator in the Keycloak console from the Docker host (§11, item 1).
3. Change the password if prompted, then scan the QR code with Google Authenticator, Microsoft Authenticator, Authy or FreeOTP, and enter the 6-digit code.
4. You arrive at the Executive Overview. In the demo profile it is already populated, and the data changes every minute.

---

## 11. Step 8: post-deployment hardening

Do these in order. Details are in the [Maintenance Manual §4](MAINTENANCE_MANUAL.md#4-first-day-configuration-checklist).

1. **First real administrator** (production). From the Docker host:
   1. Run `ssh -L 8443:localhost:443 cisoops@<host>`.
   2. Open `https://localhost:8443/auth/admin/` and sign in as `kcadmin`, using the password in `secrets/kc_bootstrap_admin_password`.
   3. Open realm **ciso** → Users → *Add user*.
   4. Under Credentials, set a temporary password; under Role mapping, add `administrator`.
2. **Demo installations exposed beyond a laptop:** delete or disable `admin` (System & Users), and set the minimum password length back to 12 or more (Configuration → Identity & enrolment).
3. **Configuration → Network access:** restrict client networks and the admin console.
4. **Configuration → Deployment:** confirm the public URL and alternative names. The status strip must show *no drift*.
5. **Configuration → Host operating system:**
   1. Download the Ubuntu or RHEL script.
   2. Review it, then run `sudo bash ciso-host-baseline-<os>.sh --dry-run --app-dir /opt/ciso-dashboard`.
   3. Run it again without `--dry-run`.

   This configures NTP, the edge firewall, SSH restriction, updates, auditd, syslog to the SIEM and Docker log rotation.
6. **Move `certs/ca.key` offline** (generated CA).
7. **Schedule backups** (Maintenance Manual §8.2) and **test a restore** once.
8. **Enrol users, then add connectors** ([API & Integration Guide, Part B](API_AND_INTEGRATION_GUIDE.md#part-b-integration-requirements-and-guidelines)).
9. Run `./scripts/smoke-test.sh` again and file the output.

---

## 12. Moving an existing installation to another system

This keeps all data, audit history, users and their authenticator enrolments.

**On the old system**
1. Announce a maintenance window, then stop user activity: `docker compose stop gateway`.
2. Back up both databases (Maintenance Manual §8.2):

   ```bash
   for db in ciso keycloak; do
     docker compose exec -T postgres sh -c "PGPASSWORD=\"\$POSTGRES_PASSWORD\" pg_dump -U \"\$POSTGRES_USER\" -Fc $db" > "$db.dump"
   done
   ```

3. Archive the **same** keys and configuration: `tar czf keys.tgz .env secrets certs`.
4. Copy `ciso.dump`, `keycloak.dump` and `keys.tgz` to the new host over an encrypted channel (`scp`). Delete the plain copies afterwards.

**On the new system**
1. Do Steps 1–2 (prepare the host, clone **the same or a newer** release).
2. Restore the keys: `tar xzf keys.tgz`. **Do not run `generate-certs.sh` or `generate-secrets.sh`.**
3. If the operator's UID differs from the old host, set `APP_UID` and `APP_GID` in `.env` to `$(id -u)` and `$(id -g)`. Then fix ownership: `chown -R "$(id -u):$(id -g)" secrets certs .env`.
4. Start only the database, then restore both dumps:

   ```bash
   docker compose up -d --wait postgres
   for db in keycloak ciso; do
     docker compose exec -T postgres sh -c "PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -U \"\$POSTGRES_USER\" -d postgres -tc \"SELECT 1 FROM pg_database WHERE datname='$db'\" | grep -q 1 || PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -U \"\$POSTGRES_USER\" -d postgres -c 'CREATE DATABASE $db'"
     docker compose exec -T postgres sh -c "PGPASSWORD=\"\$POSTGRES_PASSWORD\" pg_restore -U \"\$POSTGRES_USER\" -d $db --clean --if-exists --exit-on-error" < "$db.dump"
   done
   ```

5. Run `docker compose up -d --build --wait`. `migrate` applies any newer migrations.
6. **If the address changes:** point DNS at the new host, or:
   1. Edit `PUBLIC_BASE_URL` and `CERT_SANS` in `.env`.
   2. Re-issue the certificate: `FORCE=1 CERT_SANS=<names> ./scripts/generate-certs.sh <new-name>`.
   3. Run `docker compose up -d --wait`. `idp-init` re-points the sign-in redirects automatically.
7. Verify:
   - `./scripts/smoke-test.sh`
   - Audit Log → **Verify integrity** shows *valid*, which proves the audit key matches
   - Integrations → **Test** one connector, which proves the encryption keys match
   - sign in with an existing user and their existing authenticator, which proves the Keycloak data moved
8. Keep the old host stopped (not deleted) until users confirm. Then decommission it (Maintenance Manual §15).

> Connectors call your tools from the new host's IP. Update vendor allow lists and firewall rules **before** the cut-over.

---

## 13. Offline (air-gapped) deployment

The images are built from source, so the build needs internet access. Build on a connected machine **of the same CPU architecture** (usually x86-64), then transfer.

**On the connected build machine**
```bash
git clone https://github.com/subas-007/CISO_DASHBOARD.git && cd CISO_DASHBOARD
docker compose build
docker pull postgres:17-alpine && docker pull quay.io/keycloak/keycloak:26.4
docker save ciso-dashboard/api:1.0.0 ciso-dashboard/gateway:1.0.0 postgres:17-alpine quay.io/keycloak/keycloak:26.4 \
  | gzip > ciso-images.tar.gz
git archive --format=tar.gz -o ciso-source.tar.gz HEAD
sha256sum ciso-images.tar.gz ciso-source.tar.gz > SHA256SUMS
```

**Transfer** `ciso-images.tar.gz`, `ciso-source.tar.gz` and `SHA256SUMS` through your approved media process.

**On the offline host**
```bash
sha256sum -c SHA256SUMS
mkdir -p /opt/ciso-dashboard && tar xzf ciso-source.tar.gz -C /opt/ciso-dashboard && cd /opt/ciso-dashboard
gunzip -c /path/to/ciso-images.tar.gz | docker load
# then Steps 3 and 4 as normal, and start WITHOUT building:
docker compose up -d --no-build --wait
./scripts/smoke-test.sh
```

Offline differences:
- The **CISA KEV** threat feed needs `www.cisa.gov`. Disable it, or point it at an internal mirror (Integrations → CISA KEV → Base URL).
- Connectors work as normal when the security tools are reachable on the internal network. Untick *Block RFC 1918* if it was set.
- For updates, repeat the build-and-transfer process with the new release, then follow Maintenance Manual §10.1 using `--no-build`.

---

## 14. Deploying behind a load balancer or reverse proxy

| Requirement | Detail |
|-------------|--------|
| TLS | **TLS passthrough** (TCP mode), or **re-encryption** to the gateway's HTTPS port. The gateway accepts only HTTPS on its application port; plain HTTP is answered with a redirect only |
| Health check | `GET https://<backend>/api/ready`, expecting 200 |
| Client IP | In HTTP mode, the balancer must send `X-Forwarded-For`. Add the balancer addresses to `TRUSTED_UPSTREAM_PROXIES` (or Configuration → Deployment → *Trusted load balancers*, then apply). Without this, every user appears to come from the balancer, and per-IP limits and network allow lists stop working |
| Public URL | `PUBLIC_BASE_URL` = the address users type, which is the balancer's name. Put that name in the certificate SANs too |
| Live updates (SSE) | `/api/stream` is a long-lived response. Turn off response buffering, and set the idle timeout above 60 s. The server sends a keep-alive every 25 s, and a stream lasts up to the access-token lifetime |
| Sticky sessions | Not needed. Sessions are stored in the database |
| Headers | Pass `Host`, `Origin` and `Sec-Fetch-Site` unchanged. CSRF protection compares `Origin` with the public URL |

---

## 15. Ports and firewall summary

| Port | Direction | Purpose | Restrict to |
|------|-----------|---------|-------------|
| 443/tcp (`HTTPS_PORT`) | inbound | Web application, API, sign-in | User networks, or the load balancer |
| 80/tcp (`HTTP_PORT`) | inbound | Redirect to HTTPS (optional) | Same as 443, or close it |
| 22/tcp | inbound | SSH administration | Admin networks (host baseline) |
| 443/tcp | outbound | Security tool APIs, `www.cisa.gov`, and image registries at build time | Tool addresses |
| 123/udp | outbound | NTP | NTP servers |
| 6514/tcp | outbound | Syslog over TLS to the SIEM (optional) | SIEM collector |

PostgreSQL and Keycloak are **never** published; they live on internal Docker networks. Docker-published ports bypass ufw and firewalld. The host baseline script therefore filters them in the `DOCKER-USER` chain.

> The HTTP→HTTPS redirect always targets port 443. If you publish HTTPS on another port, give users the full `https://…:<port>` address.

---

## 16. Troubleshooting a first deployment

| Symptom | Cause | Fix |
|---------|-------|-----|
| `generate-secrets.sh`: *.env already exists* | Re-run on an installed system | Use `--upgrade` to add missing values. Use `--force` only on a brand-new system you intend to wipe |
| `generate-certs.sh`: *certs/ already populated* | Re-run | `FORCE=1 …` re-issues the service certificate under the existing CA |
| `bind: address already in use` on 443 or 80 | Another web server is running | Stop it, or set `HTTPS_PORT` / `HTTP_PORT` in `.env` (and the port in `PUBLIC_BASE_URL`) |
| `permission denied` reading `/run/secrets/…`; `api` or `idp-init` exits | Files owned by a different UID from `APP_UID` (scripts run with `sudo`, or the Windows UID not changed) | Set `APP_UID` / `APP_GID` to the file owner's IDs (`1000` on Windows); `chown` the files; `docker compose up -d --wait` |
| `--wait` fails; `idp-init` exited non-zero | Keycloak not ready yet, or the bootstrap password doesn't match an existing Keycloak database (for example a leftover volume from an earlier attempt) | `docker compose logs idp-init`. For a fresh system with a stale volume: `docker compose down -v`, then start again |
| Browser: *NET::ERR_CERT_AUTHORITY_INVALID* | CA not trusted on the client | §10.1 |
| Browser: *NET::ERR_CERT_COMMON_NAME_INVALID* | The address used is not in the certificate | Use the public URL, or add the name to `CERT_SANS` and re-issue (§6) |
| Redirected to a different host name (308) | You used an alternative name. The gateway sends everyone to the public URL | Expected behaviour |
| Sign-in page shows *Invalid parameter: redirect_uri* | `PUBLIC_BASE_URL` changed, but `idp-init` has not re-run | `docker compose up -d --wait` (re-runs `idp-init`) |
| Authenticator codes always rejected | Clock drift, or a non-SHA1 TOTP algorithm | Fix NTP; keep HmacSHA1 (Configuration → Identity) |
| Smoke test can't connect | The host can't resolve or reach the public URL | Add a hosts entry on the Docker host (§4.5) |
| First build fails downloading packages | No outbound internet, or a proxy is required | Set `HTTP_PROXY` / `HTTPS_PROXY` for the Docker daemon, or use §13 |
| Users on some networks can't reach the dashboard; `Pool overlaps with other one on this address space` | **Address overlap:** your network uses part of 172.30.0.0/16 | Before the first start, choose a free /16 and change it in three places: the four `subnet:` lines at the end of `docker-compose.yml`; `CONNECTOR_BLOCKED_CIDRS` in `docker-compose.yml`; and `allow 172.30.0.1;` in `infra/nginx/nginx.conf`, which becomes the `.0.1` of your new first subnet (the Docker host's address on the edge network) |
| Containers or volumes from another installation appear, or data is missing | Two installations on one host share the project name `ciso-dashboard` | One installation per host (§3). Never run `docker compose down -v` without checking which installation you are in |

---

## 17. Starting over or removing an installation

```bash
docker compose down            # stop; keeps data (volume pgdata)
docker compose down -v         # stop and DELETE all data (fresh start)
rm -rf .env secrets certs      # only for a fresh start where nothing must be kept
```

> `docker compose down -v` deletes the dashboard database, the identities and every MFA enrolment. Take a backup first unless the system is disposable. To decommission production, follow the Maintenance Manual §15.

---

## 18. Deployment sign-off checklist

| # | Check | Evidence | ✓ |
|---|-------|----------|---|
| 1 | Decisions in §2 recorded, including the deployed commit or tag | Build record | |
| 2 | Host meets §3; time synchronised | `timedatectl`, `docker compose version` | |
| 3 | Certificate covers the public name and alternative names; expiry recorded | `openssl x509 … -ext subjectAltName` | |
| 4 | `.env`, `secrets/` and `certs/` archived to the vault | Vault reference | |
| 5 | All services healthy; `migrate` and `idp-init` exited 0 | `docker compose ps -a` | |
| 6 | Smoke test: **63 passed, 0 failed** | Output file | |
| 7 | First administrator signs in with TOTP | Audit log `auth.login.first` | |
| 8 | Demo admin removed, or the system is a demonstration only | System & Users | |
| 9 | Network access, deployment profile and identity policy reviewed | Configuration audit records | |
| 10 | Host baseline applied | Script output | |
| 11 | Backups scheduled and one restore tested | Restore test log | |
| 12 | Monitoring on `/api/ready`; logs shipped to the SIEM | Monitoring and SIEM screenshots | |
