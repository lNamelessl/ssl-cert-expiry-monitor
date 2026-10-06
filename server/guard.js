// Check-start target guard. The product is monitoring of PUBLIC domains that
// the operator names; to keep the service from being abused as an internal
// port scanner, check-start is refused when the target (literal or resolved)
// is loopback, link-local / cloud-metadata (169.254.169.254), unspecified, or
// multicast. Private LAN ranges (RFC1918, IPv6 ULA) are ALLOWED on purpose —
// monitoring a LAN host is a legitimate use and documented as such.
import net from 'node:net';
import dns from 'node:dns/promises';

export class GuardError extends Error {}

function ipv4Reason(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return 'malformed IPv4';
  }
  const [a, b] = parts;
  if (a === 127) return 'IPv4 loopback';
  if (a === 169 && b === 254) return 'IPv4 link-local (includes cloud metadata 169.254.169.254)';
  if (a === 0) return 'IPv4 this-network (unspecified)';
  if (a >= 224 && a <= 239) return 'IPv4 multicast';
  if (a >= 240) return 'IPv4 reserved';
  return null; // includes RFC1918 (10/8, 172.16/12, 192.168/16) — allowed
}

function expandIpv6(ip) {
  if (!ip.includes(':')) return null;
  let head = ip;
  let tail = '';
  const dc = ip.indexOf('::');
  if (dc !== -1) {
    if (ip.indexOf('::', dc + 1) !== -1) return null; // more than one "::"
    head = ip.slice(0, dc);
    tail = ip.slice(dc + 2);
  }
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  if ([...h, ...t].some((g) => g.includes('.'))) return null; // embedded IPv4 handled elsewhere
  const fill = dc === -1 ? 0 : 8 - (h.length + t.length);
  if (fill < 0) return null;
  if (dc === -1 && h.length + t.length !== 8) return null;
  const groups = [...h, ...Array(fill).fill('0'), ...t];
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => Number.parseInt(g, 16));
  if (nums.some((n) => !Number.isFinite(n))) return null;
  return nums;
}

function ipv6Reason(ip) {
  const s = ip.toLowerCase();
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return ipv4Reason(mapped[1]);
  if (s === '::') return 'IPv6 unspecified';
  if (s === '::1') return 'IPv6 loopback';
  const groups = expandIpv6(s);
  if (!groups) return null; // unparseable — let the TLS layer fail naturally
  const g0 = groups[0];
  if (g0 >= 0xfe80 && g0 <= 0xfebf) return 'IPv6 link-local';
  if (g0 >= 0xff00 && g0 <= 0xffff) return 'IPv6 multicast';
  return null;
}

export function forbiddenReason(address) {
  if (net.isIPv4(address)) return ipv4Reason(address);
  if (net.isIPv6(address)) return ipv6Reason(address);
  return null;
}

// Throws GuardError when the target must not be dialed.
export async function assertAllowed(host) {
  if (net.isIP(host)) {
    const reason = forbiddenReason(host);
    if (reason) throw new GuardError(`forbidden target ${host}: ${reason}`);
    return;
  }
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true, verbatim: true });
  } catch (err) {
    throw new GuardError(`cannot resolve ${host}: ${err.code || err.message}`);
  }
  for (const { address } of addrs) {
    const reason = forbiddenReason(address);
    if (reason) {
      throw new GuardError(`forbidden target ${host}: resolves to ${address} (${reason})`);
    }
  }
}
