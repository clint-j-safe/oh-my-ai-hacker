#!/usr/bin/env bash
# usage: audit.sh "purpose" -- <command...>
purpose="$1"; shift
[ "$1" = "--" ] && shift
t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
out=$("$@" 2>&1); rc=$?
printf "%s | %s | cmd: %s | rc=%s\n" "$t" "$purpose" "$*" "$rc" >> /opt/engage-bb/audit.log
echo "$out"
