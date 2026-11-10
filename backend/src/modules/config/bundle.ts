/**
 * Renders administrator-defined deployment and host-OS parameters into artefacts an
 * operator applies on the Docker host. The dashboard never executes anything on the
 * host itself (no web-to-root path); every value was validated by the settings schema
 * and is additionally shell-quoted here.
 */
import { createHash } from 'node:crypto';
import net from 'node:net';
import type { SettingValue } from '../settings/settings.service.js';

type Deployment = SettingValue<'deployment'>;
type HostOs = SettingValue<'hostOs'>;

/** POSIX single-quote escaping. */
export const q = (v: string | number): string => `'${String(v).replace(/'/g, `'\\''`)}'`;

const header = (title: string, actor: string, lines: string[]) =>
  [`# ${title}`, `# Generated ${new Date().toISOString()} by ${actor.replace(/[^\w .@()-]/g, '')} (Configuration page).`, ...lines.map((l) => `# ${l}`)].join('\n');

export function certificateSans(d: Deployment): string[] {
  const host = new URL(d.publicBaseUrl).hostname.replace(/^\[|\]$/g, '');
  return [...new Set([host, ...d.alternativeNames])];
}

export function renderDeploymentEnv(d: Deployment, actor: string): string {
  const body = [
    `PUBLIC_BASE_URL=${d.publicBaseUrl}`,
    `HTTPS_PORT=${d.httpsPort}`,
    `HTTP_PORT=${d.httpPort}`,
    `CERT_SANS=${certificateSans(d).join(',')}`,
    `TRUSTED_UPSTREAM_PROXIES=${d.trustedUpstreamProxies.join(',')}`,
    `EDGE_RATE_LIMIT_RPS=${d.edgeRatePerSec}`,
    `EDGE_AUTH_RATE_LIMIT_RPS=${d.edgeAuthRatePerSec}`,
    `API_MEMORY=${d.apiMemoryMb}m`,
    `KEYCLOAK_MEMORY=${d.keycloakMemoryMb}m`,
    `POSTGRES_MEMORY=${d.postgresMemoryMb}m`,
  ].join('\n');
  const digest = createHash('sha256').update(body).digest('hex');
  return `${header('CISO Dashboard — deployment profile (contains no secrets)', actor, [
    'Apply on the Docker host from the installation directory:',
    '  scripts/apply-deployment.sh deployment.env',
    `sha256(body) = ${digest}`,
  ])}\n${body}\n`;
}

/* ------------------------------- Host script ------------------------------- */

/** Shell variable used by the generated firewall helper for its own dry-run mode. */
const DRY = '${DRY}';
const family = (cidr: string) => (net.isIPv6(cidr.split('/')[0]!) ? 6 : 4);

export function renderHostScript(h: HostOs, d: Deployment, actor: string): string {
  const ubuntu = h.targetOs === 'ubuntu';
  const pkg = (names: string) => (ubuntu ? `run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q ${names}` : `run dnf install -y -q ${names}`);
  const out: string[] = [];
  const add = (...lines: string[]) => out.push(...lines);

  add(
    '#!/usr/bin/env bash',
    header(`CISO Dashboard — host OS baseline for ${ubuntu ? 'Ubuntu 22.04/24.04' : 'RHEL / Rocky / Alma 8-9'}`, actor, [
      'Review before running. Usage:',
      '  sudo bash ciso-host-baseline.sh --dry-run    # print every change, modify nothing',
      '  sudo bash ciso-host-baseline.sh [--app-dir /opt/ciso-dashboard]',
      'Idempotent: safe to run again after changing the parameters.',
    ]),
    'set -euo pipefail',
    'DRY_RUN=0',
    'APP_DIR="$(pwd)"',
    'while [[ $# -gt 0 ]]; do',
    '  case "$1" in',
    '    --dry-run) DRY_RUN=1 ;;',
    '    --app-dir) APP_DIR="$2"; shift ;;',
    '    *) echo "unknown option: $1" >&2; exit 2 ;;',
    '  esac',
    '  shift',
    'done',
    'log() { printf "\\n==> %s\\n" "$*"; }',
    'run() { if (( DRY_RUN )); then printf "[dry-run] %s\\n" "$*"; else "$@"; fi; }',
    '# write_file <path> <mode>  (content on stdin; atomic replace)',
    'write_file() {',
    '  local path="$1" mode="$2" content',
    '  content="$(cat)"',
    '  if (( DRY_RUN )); then printf "[dry-run] write %s (%s):\\n%s\\n" "$path" "$mode" "$content"; return; fi',
    '  install -d -m 0755 "$(dirname "$path")"',
    '  printf "%s\\n" "$content" > "$path.ciso-tmp" && chmod "$mode" "$path.ciso-tmp" && mv -f "$path.ciso-tmp" "$path"',
    '}',
    '# managed_block <file> <content on stdin>: replaces the block between CISO markers',
    'managed_block() {',
    '  local file="$1" content',
    '  content="$(cat)"',
    '  if (( DRY_RUN )); then printf "[dry-run] managed block in %s:\\n%s\\n" "$file" "$content"; return; fi',
    '  touch "$file"',
    '  sed -i "/^# BEGIN CISO-DASHBOARD/,/^# END CISO-DASHBOARD/d" "$file"',
    '  printf "# BEGIN CISO-DASHBOARD\\n%s\\n# END CISO-DASHBOARD\\n" "$content" >> "$file"',
    '}',
    'if (( ! DRY_RUN )) && [[ $EUID -ne 0 ]]; then echo "Run as root (sudo), or use --dry-run" >&2; exit 1; fi',
    '. /etc/os-release',
    ubuntu
      ? 'case " ${ID:-} ${ID_LIKE:-} " in *" ubuntu "*|*" debian "*) ;; *) echo "This script targets Ubuntu/Debian; detected ${ID:-unknown}" >&2; exit 1 ;; esac'
      : 'case " ${ID:-} ${ID_LIKE:-} " in *" rhel "*|*" fedora "*|*" centos "*) ;; *) echo "This script targets RHEL-family systems; detected ${ID:-unknown}" >&2; exit 1 ;; esac',
  );
  if (ubuntu) add('run apt-get update -q');

  // Time
  add('', `log ${q(`Time zone: ${h.timezone}`)}`, `run timedatectl set-timezone ${q(h.timezone)}`);
  if (h.ntpServers.length) {
    const conf = ubuntu ? '/etc/chrony/chrony.conf' : '/etc/chrony.conf';
    add(
      '',
      `log ${q(`NTP via chrony: ${h.ntpServers.join(', ')}`)}`,
      pkg('chrony'),
      `if (( ! DRY_RUN )); then sed -i -E 's/^(pool|server) /# disabled by ciso-dashboard: &/' ${conf}; fi`,
      `managed_block ${conf} <<'EOF'`,
      ...h.ntpServers.map((s) => `server ${s} iburst`),
      'EOF',
      `run systemctl enable --now ${ubuntu ? 'chrony' : 'chronyd'}`,
      `run systemctl restart ${ubuntu ? 'chrony' : 'chronyd'}`,
    );
  }

  // DNS
  if (h.dnsServers.length) {
    add('', `log ${q(`DNS resolvers: ${h.dnsServers.join(', ')}`)}`);
    if (ubuntu) {
      add(`write_file /etc/systemd/resolved.conf.d/60-ciso-dashboard.conf 0644 <<'EOF'`, '[Resolve]', `DNS=${h.dnsServers.join(' ')}`, 'EOF', 'run systemctl restart systemd-resolved');
    } else {
      add(`write_file /etc/NetworkManager/conf.d/60-ciso-dashboard-dns.conf 0644 <<'EOF'`, '[global-dns-domain-*]', `servers=${h.dnsServers.join(',')}`, 'EOF', 'run systemctl reload NetworkManager');
    }
  }

  // Syslog forwarding
  const fwd = '/etc/rsyslog.d/60-ciso-dashboard-forward.conf';
  if (h.syslog.enabled && h.syslog.host) {
    const caFile = ubuntu ? '/etc/ssl/certs/ca-certificates.crt' : '/etc/pki/tls/certs/ca-bundle.crt';
    const tls = h.syslog.protocol === 'tls';
    add('', `log ${q(`Forward system logs to ${h.syslog.host}:${h.syslog.port} (${h.syslog.protocol})`)}`, pkg(tls ? 'rsyslog rsyslog-gnutls' : 'rsyslog'), `write_file ${fwd} 0644 <<'EOF'`);
    if (tls) add(`global(DefaultNetstreamDriverCAFile="${caFile}")`);
    add(
      `action(type="omfwd" target="${h.syslog.host}" port="${h.syslog.port}" protocol="${h.syslog.protocol === 'udp' ? 'udp' : 'tcp'}"` +
        (tls ? ` StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="${h.syslog.host}"` : '') +
        ' queue.type="LinkedList" queue.size="10000" queue.filename="ciso_fwd" action.resumeRetryCount="-1")',
      'EOF',
      'run systemctl restart rsyslog',
    );
  } else {
    add('', 'log "Syslog forwarding disabled"', `if [[ -f ${fwd} ]]; then run rm -f ${fwd}; run systemctl restart rsyslog; fi`);
  }

  // Firewall
  if (h.firewall.enabled) {
    const open = h.firewall.httpsAllowedCidrs.some((c) => c === '0.0.0.0/0' || c === '::/0');
    add('', `log ${q('Edge firewall for published ports (Docker DOCKER-USER chain)')}`);
    if (open) {
      add('echo "HTTPS is allowed from any network — removing any previous edge restriction"', 'if systemctl list-unit-files ciso-edge-firewall.service >/dev/null 2>&1; then run systemctl disable --now ciso-edge-firewall.service || true; fi');
    } else {
      // Docker-published ports bypass ufw/firewalld INPUT rules; filter them in DOCKER-USER
      // by the original destination port (post-DNAT the packet targets the container port).
      const rules: string[] = [];
      for (const v of [4, 6] as const) {
        const ipt = v === 4 ? 'iptables' : 'ip6tables';
        const cidrs = h.firewall.httpsAllowedCidrs.filter((c) => family(c) === v);
        rules.push(`${DRY}${ipt} -N CISO-EDGE 2>/dev/null || true`, `${DRY}${ipt} -F CISO-EDGE`);
        for (const c of cidrs) rules.push(`${DRY}${ipt} -A CISO-EDGE -s ${c} -j RETURN`);
        rules.push(`${DRY}${ipt} -A CISO-EDGE -j DROP`);
        for (const port of [d.httpsPort, d.httpPort]) {
          const match = `-p tcp -m conntrack --ctorigdstport ${port} --ctdir ORIGINAL -j CISO-EDGE`;
          rules.push(`${ipt} -C DOCKER-USER ${match} 2>/dev/null || ${DRY}${ipt} -I DOCKER-USER 1 ${match}`);
        }
      }
      add(
        `write_file /usr/local/sbin/ciso-edge-firewall.sh 0750 <<'EOF'`,
        '#!/usr/bin/env bash',
        '# Managed by ciso-dashboard: restricts the published HTTPS/HTTP ports to approved networks.',
        'set -euo pipefail',
        'DRY="${DRY:-}"',
        ...rules,
        'EOF',
        `write_file /etc/systemd/system/ciso-edge-firewall.service 0644 <<'EOF'`,
        '[Unit]',
        'Description=CISO Dashboard edge firewall (DOCKER-USER)',
        'After=docker.service',
        'Requires=docker.service',
        '[Service]',
        'Type=oneshot',
        'RemainAfterExit=yes',
        'ExecStart=/usr/local/sbin/ciso-edge-firewall.sh',
        '[Install]',
        'WantedBy=multi-user.target',
        'EOF',
        'run systemctl daemon-reload',
        'run systemctl enable ciso-edge-firewall.service',
        'run systemctl restart ciso-edge-firewall.service',
      );
    }
    if (h.firewall.sshAllowedCidrs.length) {
      add('', `log ${q(`SSH (port ${h.firewall.sshPort}) restricted to ${h.firewall.sshAllowedCidrs.join(', ')}`)}`);
      if (ubuntu) {
        add(pkg('ufw'), 'run ufw default allow outgoing', ...h.firewall.sshAllowedCidrs.map((c) => `run ufw allow from ${q(c)} to any port ${h.firewall.sshPort} proto tcp`), 'run ufw default deny incoming', 'run ufw --force enable');
      } else {
        add(
          pkg('firewalld'),
          'run systemctl enable --now firewalld',
          ...h.firewall.sshAllowedCidrs.map(
            (c) => `run firewall-cmd --permanent --add-rich-rule=${q(`rule family="ipv${family(c)}" source address="${c}" port port="${h.firewall.sshPort}" protocol="tcp" accept`)}`,
          ),
          'run firewall-cmd --permanent --remove-service=ssh || true',
          'run firewall-cmd --reload',
        );
      }
    } else {
      add('', 'log "SSH firewall rules left unchanged (no SSH networks defined)"');
    }
  }

  // Updates
  if (h.autoSecurityUpdates) {
    add('', 'log "Automatic security updates"');
    if (ubuntu) {
      add(pkg('unattended-upgrades'), `write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'`, 'APT::Periodic::Update-Package-Lists "1";', 'APT::Periodic::Unattended-Upgrade "1";', 'EOF');
    } else {
      add(
        pkg('dnf-automatic'),
        `if (( ! DRY_RUN )); then sed -i -E 's/^upgrade_type *=.*/upgrade_type = security/; s/^apply_updates *=.*/apply_updates = yes/' /etc/dnf/automatic.conf; fi`,
        'run systemctl enable --now dnf-automatic.timer',
      );
    }
  }

  // Kernel hardening (keeps net.ipv4.ip_forward, which Docker requires)
  if (h.kernelHardening) {
    add(
      '',
      'log "Kernel network hardening (sysctl)"',
      `write_file /etc/sysctl.d/60-ciso-dashboard-hardening.conf 0644 <<'EOF'`,
      'net.ipv4.conf.all.accept_redirects = 0',
      'net.ipv4.conf.default.accept_redirects = 0',
      'net.ipv4.conf.all.send_redirects = 0',
      'net.ipv4.conf.all.accept_source_route = 0',
      'net.ipv4.conf.all.log_martians = 1',
      'net.ipv4.icmp_echo_ignore_broadcasts = 1',
      'net.ipv4.tcp_syncookies = 1',
      'net.ipv6.conf.all.accept_redirects = 0',
      'net.ipv6.conf.all.accept_source_route = 0',
      'kernel.kptr_restrict = 2',
      'kernel.dmesg_restrict = 1',
      'kernel.yama.ptrace_scope = 1',
      'fs.protected_hardlinks = 1',
      'fs.protected_symlinks = 1',
      'fs.suid_dumpable = 0',
      'EOF',
      'run sysctl --system',
    );
  }

  // auditd
  if (h.auditd) {
    add(
      '',
      'log "auditd rules for Docker and application secrets"',
      pkg(ubuntu ? 'auditd' : 'audit'),
      'write_file /etc/audit/rules.d/60-ciso-dashboard.rules 0640 <<EOF',
      '-w /usr/bin/docker -p x -k ciso-docker',
      '-w /etc/docker -p wa -k ciso-docker',
      '-w /var/lib/docker/volumes -p wa -k ciso-docker',
      '-w ${APP_DIR}/secrets -p rwa -k ciso-secrets',
      '-w ${APP_DIR}/certs -p rwa -k ciso-secrets',
      '-w ${APP_DIR}/.env -p rwa -k ciso-secrets',
      'EOF',
      'run systemctl enable --now auditd',
      'run augenrules --load',
    );
  }

  // Docker daemon log rotation
  add(
    '',
    `log ${q(`Docker default log rotation: ${h.dockerLogMaxSizeMb} MB x ${h.dockerLogMaxFiles}`)}`,
    'DAEMON_JSON=/etc/docker/daemon.json',
    `LOG_OPTS='{"log-driver":"json-file","log-opts":{"max-size":"${h.dockerLogMaxSizeMb}m","max-file":"${h.dockerLogMaxFiles}"}}'`,
    'if [[ ! -s "$DAEMON_JSON" ]]; then',
    '  printf "%s\\n" "$LOG_OPTS" | write_file "$DAEMON_JSON" 0644',
    'elif command -v jq >/dev/null 2>&1; then',
    '  jq --argjson o "$LOG_OPTS" ". + \\$o" "$DAEMON_JSON" | write_file "$DAEMON_JSON" 0644',
    'else',
    '  echo "NOTE: $DAEMON_JSON exists and jq is not installed — merge manually: $LOG_OPTS"',
    'fi',
    'echo "NOTE: daemon log options apply to newly created containers; the dashboard services already rotate logs (compose)."',
    '',
    'log "Host baseline applied"',
  );
  return `${out.join('\n')}\n`;
}
