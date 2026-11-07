# Drives egress-report (egress-report.sh, packaged in flake.nix)
# against a synthesized capture: DNS query/answer, a TLS ClientHello with
# SNI, and raw TCP/UDP flows with no hostname. Covers the summarize
# sections, allowlist matching (subdomain + "*." and ":port" tolerance,
# exit 2 on violations), follow mode's live alert lines, and verdict over
# proxy audit logs: clean, not clean, unreadable, missing.
{ pkgs, lib, egressReport }:

pkgs.runCommand "egress-report-test"
  {
    nativeBuildInputs = [ egressReport pkgs.python3 ];
  } ''
    set -euo pipefail
    export HOME="$TMPDIR"  # tshark wants somewhere for its config state

    python3 ${./make-egress-pcap.py} session.pcap

    echo "--- summarize, no allowlist"
    egress-report summarize session.pcap | tee report.txt
    grep -q 'api\.anthropic\.com' report.txt
    grep -q 'evil\.example\.com' report.txt
    grep -q '203\.0\.113\.7:4444' report.txt
    grep -q '203\.0\.113\.9:123' report.txt
    # The address the DNS answer named must be attributed, not "no hostname".
    if grep -q '198\.51\.100\.10:443' report.txt; then
      echo "FAIL: DNS-attributed destination listed as having no hostname" >&2
      exit 1
    fi
    if grep -q 'allowlist violations' report.txt; then
      echo "FAIL: violations section printed without an allowlist" >&2
      exit 1
    fi
    # IPv6: AAAA answers attribute v6 flows; unknown ones print as [addr]:port.
    grep -q 'v6\.example\.net' report.txt
    grep -qF '[2001:db8::bad]:443' report.txt
    if grep -q '2001:db8::10' report.txt; then
      echo "FAIL: AAAA-attributed v6 destination listed as having no hostname" >&2
      exit 1
    fi
    # Inbound replies and resolver meta-traffic count nothing.
    if grep -q '10\.0\.2\.15' report.txt; then
      echo "FAIL: inbound reply to the guest counted as a destination" >&2
      exit 1
    fi
    if grep -q 'claude-vm' report.txt; then
      echo "FAIL: single-label hostname lookup counted as an egress domain" >&2
      exit 1
    fi

    cat > allow.txt <<'EOF'
    # exercises comment stripping, "*." and ":port" tolerance
    *.anthropic.com:443
    pool.ntp.org
    EOF

    echo "--- summarize with allowlist (expect exit 2)"
    rc=0
    egress-report summarize session.pcap --allowlist allow.txt > report2.txt || rc=$?
    cat report2.txt
    [ "$rc" -eq 2 ]
    grep -A2 'allowlist violations:' report2.txt | grep -q 'evil\.example\.com'
    if grep -A2 'allowlist violations:' report2.txt | grep -q 'api\.anthropic\.com'; then
      echo "FAIL: allowlisted domain reported as a violation" >&2
      exit 1
    fi

    echo "--- follow mode"
    egress-report follow session.pcap --allowlist allow.txt --alerts alerts.log &
    follow_pid=$!
    for _ in $(seq 1 100); do
      grep -q 'evil\.example\.com' alerts.log 2>/dev/null && break
      sleep 0.2
    done
    kill "$follow_pid" 2>/dev/null || true
    grep -q 'egress-alert: evil\.example\.com' alerts.log
    if grep -q 'api\.anthropic\.com' alerts.log; then
      echo "FAIL: follow mode alerted on an allowlisted domain" >&2
      exit 1
    fi

    echo "--- verdict"
    # Lines as the proxy writes them (slog JSON, proxy.go Proxy.log).
    api='{"time":"2026-11-07T10:00:00Z","level":"INFO","msg":"decision","kind":"api","host":"api.anthropic.com","port":0,"path":"/v1/messages","decision":"allow","mode":"enforce"}'
    printf '%s\n' "$api" "$api" > clean.jsonl
    verdict () { # file, want-rc
      rc=0; egress-report verdict "$1" > verdict.txt || rc=$?
      cat verdict.txt
      if [ "$rc" -ne "$2" ]; then echo "FAIL: verdict $1 exited $rc, want $2" >&2; exit 1; fi
    }

    verdict clean.jsonl 0
    [ "$(wc -l < verdict.txt)" -eq 1 ]
    grep -qx 'egress verdict: clean — 2 model-API request(s), no other egress' verdict.txt

    : > empty.jsonl
    verdict empty.jsonl 0
    grep -q 'clean — 0 model-API' verdict.txt

    # Anything other than an allowed model-API request: an allowed tunnel, a
    # denied one, a denied API path, a shadow-mode would_deny.
    cp clean.jsonl dirty.jsonl
    cat >> dirty.jsonl <<'EOF'
    {"time":"t","level":"INFO","msg":"decision","kind":"connect","host":"evil.example.com","port":443,"path":"","decision":"deny","mode":"enforce"}
    {"time":"t","level":"INFO","msg":"decision","kind":"connect","host":"evil.example.com","port":443,"path":"","decision":"deny","mode":"enforce"}
    {"time":"t","level":"INFO","msg":"decision","kind":"connect","host":"github.com","port":443,"path":"","decision":"allow","mode":"enforce"}
    {"time":"t","level":"INFO","msg":"decision","kind":"api","host":"api.anthropic.com","port":0,"path":"/v1/files","decision":"deny","mode":"enforce"}
    {"time":"t","level":"INFO","msg":"decision","kind":"http","host":"example.org","port":80,"path":"/x","decision":"would_deny","mode":"log"}
    EOF
    verdict dirty.jsonl 2
    grep -q 'NOT CLEAN — 5 decision(s) .*; 2 model-API request(s) allowed' verdict.txt
    grep -qE '^ +2  deny connect evil\.example\.com:443$' verdict.txt
    grep -qE '^ +1  allow connect github\.com:443$' verdict.txt
    grep -qE '^ +1  deny api api\.anthropic\.com/v1/files$' verdict.txt
    grep -qE '^ +1  would_deny http example\.org:80$' verdict.txt
    if grep -q 'deny api api\.anthropic\.com/v1/messages\|allow api' verdict.txt; then
      echo "FAIL: an allowed model-API request listed against the run" >&2
      exit 1
    fi

    # A log it cannot read is no evidence: a truncated last line (the proxy
    # killed mid-write), a blank line, another program's JSON.
    { cat clean.jsonl; printf '{"time":"t","msg":"deci'; } > truncated.jsonl
    verdict truncated.jsonl 65
    grep -q 'INVALID — 1 line(s) are not proxy decisions (first: line 3)' verdict.txt
    printf '%s\n\n%s\n' "$api" "$api" > blank.jsonl
    verdict blank.jsonl 65
    grep -q 'first: line 2' verdict.txt
    printf '%s\n' "$api" '{"msg":"hello","kind":"api","decision":"allow"}' > foreign.jsonl
    verdict foreign.jsonl 65
    verdict missing.jsonl 66
    rc=0; egress-report verdict clean.jsonl --allowlist allow.txt 2>/dev/null || rc=$?
    [ "$rc" -eq 64 ]

    touch $out
  ''
