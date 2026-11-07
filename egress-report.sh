# egress-report — summarize or live-watch a claude-vm egress capture.
#
# Input is the pcap that QEMU's filter-dump object writes when the launcher
# runs with EGRESS_POLICY=monitor or =alert (see mkRunnerScript in flake.nix).
# This is observation only: nothing in here can block traffic. Attribution
# comes from DNS queries/answers and TLS SNI, so traffic to a hardcoded IP —
# or with an encrypted ClientHello — shows up under "no observed hostname"
# rather than by name.
#
# Usage:
#   egress-report summarize <pcap> [--allowlist FILE]
#   egress-report follow <pcap> --allowlist FILE --alerts FILE
#   egress-report verdict <audit.jsonl>
#
# summarize prints a report to stdout; with --allowlist it appends a
# violations section and exits 2 when any observed hostname matched no entry.
# follow tails a growing capture and appends one line per newly seen
# off-allowlist hostname to the alerts file; it runs until killed.
#
# verdict reads the egress proxy's JSONL audit log (the sealed modes, not a
# pcap) and judges a run: clean when every decision is an allowed request to
# a model-API endpoint — nothing else left the VM, or even tried to. Exits 0
# clean, printing one line; 2 not clean, the line then the other decisions,
# counted; 65 when a line is not a proxy decision (a truncated or foreign
# log is no evidence of anything); 66 when there is no log. An empty log is
# clean: the proxy saw no traffic at all.
#
# Allowlist format: one domain per line, '#' starts a comment. An entry
# matches itself and every subdomain. A leading '*.' and a ':port' suffix
# are tolerated and ignored.
#
# Packaged with pkgs.writeShellApplication (flake.nix), which provides
# `set -euo pipefail` and puts tshark/gawk/jq/coreutils on PATH.

usage() {
  echo "usage: egress-report summarize <pcap> [--allowlist FILE]" >&2
  echo "       egress-report follow <pcap> --allowlist FILE --alerts FILE" >&2
  echo "       egress-report verdict <audit.jsonl>" >&2
  exit 64
}

[ $# -ge 2 ] || usage
mode="$1"
pcap="$2"
shift 2

allowlist=""
alerts=""
while [ $# -gt 0 ]; do
  case "$1" in
    --allowlist) allowlist="${2:?--allowlist needs a file}"; shift 2 ;;
    --alerts)    alerts="${2:?--alerts needs a file}";       shift 2 ;;
    *) usage ;;
  esac
done

# One tshark pass emits pipe-separated typed fields; gawk does the rest.
# '|' cannot occur in a hostname, so the separator is safe. ICMP/ICMPv6 is
# excluded everywhere: an unreachable error embeds the original packet's
# headers, and tshark would extract those as if a second connection existed.
FIELDS=(
  -T fields -E separator='|' -E occurrence=a
  -e dns.flags.response -e dns.qry.name -e dns.a -e dns.aaaa
  -e tls.handshake.extensions_server_name
  -e ip.dst -e ipv6.dst -e tcp.dstport -e udp.dstport
)
FILTER='!icmp && !icmpv6 && (dns || tls.handshake.extensions_server_name || (tcp.flags.syn == 1 && tcp.flags.ack == 0) || udp)'

# Shared gawk prelude: allowlist loading and matching. `have_allow` guards
# everything, so without -v allowfile all hostnames count as allowed.
AWK_LIB='
function norm(d) { d = tolower(d); sub(/\.$/, "", d); return d }
# Resolver meta-traffic, not egress: single-label names (the guest resolving
# its own hostname) and reverse lookups.
function is_local_name(d) { return d !~ /\./ || d ~ /\.arpa$/ }
# slirp defaults: guest v4 10.0.2.15, guest v6 inside fec0::/64. A packet
# whose destination is the guest is inbound and counts nothing.
function is_guest(a) { return a == "10.0.2.15" || a ~ /^fec0:/ }
function destkey(a, port) { return (a ~ /:/ ? "[" a "]" : a) ":" port }
function strippat(p) {
  sub(/#.*/, "", p); gsub(/[ \t\r]/, "", p)
  sub(/^\*\./, "", p); sub(/:[0-9]+$/, "", p)
  return norm(p)
}
function allowed(d,   p, suf) {
  if (!have_allow) return 1
  if (d in allowcache) return allowcache[d]
  for (p in pat) {
    suf = "." p
    if (d == p || substr(d, length(d) - length(suf) + 1) == suf)
      return allowcache[d] = 1
  }
  return allowcache[d] = 0
}
BEGIN {
  FS = "|"
  if (allowfile != "") {
    have_allow = 1
    while ((getline _l < allowfile) > 0) {
      _l = strippat(_l)
      if (_l != "") pat[_l] = 1
    }
    close(allowfile)
  }
}
'

# shellcheck disable=SC2016 # awk source, not shell — $N must stay literal
SUMMARIZE_AWK='
{
  resp = $1; qname = $2; arecs = $3 "," $4; sni = $5
  ip = ($6 != "" ? $6 : $7); tport = $8; uport = $9
  if (sni != "") {
    n = split(sni, a, ",")
    for (i = 1; i <= n; i++) {
      d = norm(a[i]); if (d == "") continue
      snicount[d]++; seen[d] = 1
      if (ip != "") byip[ip] = d
    }
  } else if (qname != "") {
    if (resp == "1" || resp == "True") {
      # DNS answer: remember address-to-name (A and AAAA), for attributing
      # raw flows.
      q = norm(qname)
      n = split(arecs, a, ",")
      for (i = 1; i <= n; i++) if (a[i] != "") byip[a[i]] = q
    } else {
      n = split(qname, a, ",")
      for (i = 1; i <= n; i++) {
        d = norm(a[i]); if (d == "" || is_local_name(d)) continue
        dnscount[d]++; seen[d] = 1
      }
    }
  } else if (tport != "" && ip != "" && !is_guest(ip)) {
    tcpdst[destkey(ip, tport)]++; dstip[destkey(ip, tport)] = ip
  } else if (uport != "" && ip != "" && !is_guest(ip)) {
    # DNS is counted above; DHCP and mDNS are local noise, not egress.
    if (uport != 53 && uport != 67 && uport != 68 && uport != 5353) {
      udpdst[destkey(ip, uport)]++; dstip[destkey(ip, uport)] = ip
    }
  }
}
function section(title, arr,   k, any) {
  print title
  PROCINFO["sorted_in"] = "@val_num_desc"
  for (k in arr) { printf "  %6d  %s\n", arr[k], k; any = 1 }
  if (!any) print "  (none)"
  print ""
}
END {
  section("domains queried (DNS):", dnscount)
  section("TLS connections by SNI:", snicount)
  # Raw flows whose address resolves to nothing we saw a name for.
  for (k in tcpdst) if (!(dstip[k] in byip)) tcporphan[k] = tcpdst[k]
  for (k in udpdst) if (!(dstip[k] in byip)) udporphan[k] = udpdst[k]
  section("TCP destinations with no observed hostname:", tcporphan)
  section("UDP destinations with no observed hostname (DNS/DHCP/mDNS excluded):", udporphan)
  if (have_allow) {
    print "allowlist violations:"
    nviol = 0
    PROCINFO["sorted_in"] = "@ind_str_asc"
    for (d in seen) if (!allowed(d)) { printf "  %s\n", d; nviol++ }
    if (!nviol) {
      print "  (none)"
    } else {
      print ""
      print "  allow a domain for the next launch with EGRESS_ALLOW=<domain>[,...],"
      print "  a line in the EGRESS_ALLOWLIST file, or launch with EGRESS_POLICY=open."
    }
    if (nviol) exit 2
  }
}
'

# shellcheck disable=SC2016 # awk source, not shell — $N must stay literal
FOLLOW_AWK='
{
  n = split($2 "," $5, a, ",")
  for (i = 1; i <= n; i++) {
    d = norm(a[i])
    if (d == "" || is_local_name(d) || d in reported) continue
    reported[d] = 1
    if (!allowed(d)) {
      printf "%s egress-alert: %s is not in the allowlist (EGRESS_ALLOW=%s allows it on the next launch)\n", \
        strftime("%Y-%m-%dT%H:%M:%S%z"), d, d >> alerts
      fflush(alerts)
    }
  }
}
'

# The audit log, one slog JSON object per line (proxy.go, Proxy.log). Lines
# are read raw, so one that is not JSON is reported by number rather than
# aborting the parse. The first output line is the outcome for the shell;
# the rest is the report. The grouping key names what was asked for: host
# and port for a tunnel or plain-HTTP request, host and path for a model-API
# one (whose port is always 0).
# shellcheck disable=SC2016 # jq source, not shell — $x must stay literal
VERDICT_JQ='
def key: "\(.decision) \(.kind) \(.host)\(if (.port // 0) > 0 then ":\(.port)" else "" end)\(if .kind == "api" then .path // "" else "" end)";
def is_decision: type == "object" and .msg == "decision"
  and (.kind | type) == "string" and (.decision | type) == "string" and (.host | type) == "string";
[inputs] | to_entries | map({n: (.key + 1), j: (.value | try fromjson catch null)}) as $r
| [$r[] | select(.j | is_decision | not) | .n] as $bad
| [$r[] | .j | select(is_decision)] as $d
| ([$d[] | select(.kind == "api" and .decision == "allow")] | length) as $api
| [$d[] | select((.kind == "api" and .decision == "allow") | not)] as $other
| if ($bad | length) > 0 then
    "invalid",
    "egress verdict: INVALID — \($bad | length) line(s) are not proxy decisions (first: line \($bad[0]))"
  elif ($other | length) > 0 then
    "dirty",
    "egress verdict: NOT CLEAN — \($other | length) decision(s) other than an allowed model-API request; \($api) model-API request(s) allowed",
    ($other | group_by(key) | sort_by(-length, (.[0] | key))[]
     | "  \(length | tostring | (" " * (6 - length)) + .)  \(.[0] | key)")
  else
    "clean",
    "egress verdict: clean — \($api) model-API request(s), no other egress"
  end
'

case "$mode" in
  verdict)
    { [ -z "$allowlist" ] && [ -z "$alerts" ]; } || usage
    log="$pcap"
    if [ ! -f "$log" ]; then
      echo "error: no audit log at $log" >&2
      exit 66
    fi
    # jq's own failures must not pass for an outcome: its exit 2 is not ours.
    if ! report="$(jq -nRr "$VERDICT_JQ" < "$log")"; then
      echo "error: cannot read the audit log at $log" >&2
      exit 65
    fi
    outcome="${report%%$'\n'*}"
    printf '%s\n' "${report#*$'\n'}"
    case "$outcome" in
      clean)   exit 0 ;;
      dirty)   exit 2 ;;
      *)       exit 65 ;;
    esac
    ;;
  summarize)
    [ -z "$alerts" ] || usage
    if [ ! -f "$pcap" ]; then
      echo "error: no capture at $pcap" >&2
      exit 66
    fi
    echo "egress report — $(basename "$pcap")"
    echo ""
    # gawk's `exit 2` (allowlist violations) propagates as this script's
    # exit code via pipefail.
    tshark -r "$pcap" -Y "$FILTER" "${FIELDS[@]}" \
      | gawk -v allowfile="$allowlist" "$AWK_LIB$SUMMARIZE_AWK"
    ;;
  follow)
    { [ -n "$allowlist" ] && [ -n "$alerts" ]; } || usage
    : >> "$alerts"
    # The capture may not exist yet when this starts: tail -F retries until
    # QEMU creates it. tshark reads the pcap stream from the pipe; -l makes
    # it emit per packet, and DNS responses/raw flows are filtered out here
    # since only query names and SNI can be matched against the allowlist.
    tail -c +1 -F "$pcap" 2>/dev/null \
      | tshark -r - -l -Y '!icmp && !icmpv6 && (dns.flags.response == 0 || tls.handshake.extensions_server_name)' "${FIELDS[@]}" 2>/dev/null \
      | gawk -v allowfile="$allowlist" -v alerts="$alerts" "$AWK_LIB$FOLLOW_AWK"
    ;;
  *)
    usage
    ;;
esac
