#!/bin/bash
# Inspect and smoke-test a built NekoBox .deb inside a matching Ubuntu image.
#
# Usage: scripts/smoke-test-package.sh --deb PATH --version VERSION \
#            [--expected-index PATH] [--series SERIES]
#
# The package is installed with dpkg (its dependencies must already be present
# in the image, normally from debian/control Build-Depends).  The GUI is
# started with Qt's offscreen platform, a fresh HOME/XDG profile and an
# explicit appdata directory.  The test passes only while the GUI is alive and
# has spawned the packaged /usr/libexec/Iblis/nekobox_core as its child with
# -waitpid <gui-pid>.  GUI processes are cleaned up by exact PID and by the
# unique appdata/waitpid markers, never by a broad pkill.
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

deb=
version=
expected_index=
series=
while [ $# -gt 0 ]; do
    case "$1" in
        --deb) shift; deb=${1:-} ;;
        --version) shift; version=${1:-} ;;
        --expected-index) shift; expected_index=${1:-} ;;
        --series) shift; series=${1:-} ;;
        -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
[ -n "$deb" ] && [ -f "$deb" ] || die "--deb must name an existing file"
[ -n "$version" ] || die "--version is required"

package_version=$(dpkg-deb -f "$deb" Version)
[ "$package_version" = "$version" ] \
    || die "package version is $package_version, expected $version"
arch=$(dpkg-deb -f "$deb" Architecture)
[ "$arch" = "amd64" ] || die "package architecture is $arch, expected amd64"

work=$(mktemp -d /tmp/nekobox-smoke.XXXXXX)
extract=$work/payload
profile=$work/profile
appdata=$profile/appdata
gui_log=$work/gui.log
deb_listing=$work/deb.list
gui_pid=
core_pid=

process_exe() {
    readlink -f "/proc/$1/exe" 2>/dev/null || true
}

process_cmdline() {
    tr '\0' ' ' <"/proc/$1/cmdline" 2>/dev/null || true
}

find_gui() {
    local pid exe cmd
    for pid in /proc/[0-9]*; do
        pid=${pid#/proc/}
        [ -r "/proc/$pid/cmdline" ] || continue
        exe=$(process_exe "$pid")
        [ "$exe" = "/usr/libexec/Iblis/nekobox" ] || continue
        cmd=$(process_cmdline "$pid")
        case "$cmd" in
            "/usr/libexec/Iblis/nekobox -appdata $appdata "*) printf '%s\n' "$pid"; return 0 ;;
        esac
    done
    return 1
}

find_core() {
    local pid exe cmd ppid
    [ -n "${gui_pid:-}" ] || return 1
    for pid in /proc/[0-9]*; do
        pid=${pid#/proc/}
        [ -r "/proc/$pid/cmdline" ] || continue
        exe=$(process_exe "$pid")
        [ "$exe" = "/usr/libexec/Iblis/nekobox_core" ] || continue
        cmd=$(process_cmdline "$pid")
        case "$cmd" in
            "/usr/libexec/Iblis/nekobox_core -waitpid $gui_pid "*) ;;
            *) continue ;;
        esac
        ppid=$(awk '/^PPid:/ { print $2; exit }' "/proc/$pid/status" 2>/dev/null || true)
        [ "$ppid" = "$gui_pid" ] || continue
        printf '%s\n' "$pid"
        return 0
    done
    return 1
}

dump_processes() {
    local pid exe cmd
    for pid in /proc/[0-9]*; do
        pid=${pid#/proc/}
        [ -r "/proc/$pid/cmdline" ] || continue
        exe=$(process_exe "$pid")
        case "$exe" in
            /usr/libexec/Iblis/nekobox|/usr/libexec/Iblis/nekobox_core)
                cmd=$(process_cmdline "$pid")
                printf 'pid=%s exe=%s cmd=%s\n' "$pid" "$exe" "$cmd" >&2
                ;;
        esac
    done
}

cleanup() {
    set +e
    local pid exe cmd any
    if [ -n "${gui_pid:-}" ]; then
        local found
        found=$(find_core || true)
        [ -n "$found" ] && core_pid=$found
    fi
    [ -n "${core_pid:-}" ] && kill -KILL "$core_pid" 2>/dev/null
    [ -n "${gui_pid:-}" ] && kill -KILL "$gui_pid" 2>/dev/null
    for _ in 1 2 3; do
        any=0
        for pid in /proc/[0-9]*; do
            pid=${pid#/proc/}
            [ -r "/proc/$pid/cmdline" ] || continue
            exe=$(process_exe "$pid")
            cmd=$(process_cmdline "$pid")
            case "$exe:$cmd" in
                "/usr/libexec/Iblis/nekobox:/usr/libexec/Iblis/nekobox -appdata $appdata "*)
                    kill -KILL "$pid" 2>/dev/null
                    any=1
                    ;;
                "/usr/libexec/Iblis/nekobox_core:"*"-waitpid ${gui_pid:-none} "*)
                    kill -KILL "$pid" 2>/dev/null
                    any=1
                    ;;
            esac
        done
        [ "$any" -eq 0 ] && break
        sleep 0.2
    done
    rm -rf "$work"
}
trap cleanup EXIT

note "extracting the package payload"
mkdir -p "$extract"
dpkg-deb -x "$deb" "$extract"
[ -x "$extract/usr/libexec/Iblis/nekobox" ] \
    || die "package payload is missing the GUI executable"
[ -x "$extract/usr/libexec/Iblis/nekobox_core" ] \
    || die "package payload is missing the core executable"

# Avoid a pipefail SIGPIPE from grep -q closing the dpkg-deb listing early.
dpkg-deb -c "$deb" >"$deb_listing"
if grep -qE '[[:space:]]\./usr/bin/sing-box$' "$deb_listing"; then
    die "package still ships the conflicting /usr/bin/sing-box wrapper"
fi

payload_index=$extract/usr/share/doc/nekobox/third-party/INDEX.txt
if [ ! -f "$payload_index" ]; then
    payload_index=$extract/usr/share/doc/nekobox/third-party/INDEX.txt.gz
fi
[ -f "$payload_index" ] || die "package payload is missing the third-party INDEX"
if [ -n "$expected_index" ]; then
    [ -f "$expected_index" ] || die "expected index not found: $expected_index"
    if [ "${payload_index%.gz}" != "$payload_index" ]; then
        gzip -dc "$payload_index" >"$work/INDEX.txt"
        payload_index=$work/INDEX.txt
    fi
    cmp -s "$expected_index" "$payload_index" \
        || die "packaged third-party INDEX differs from the repository copy"
    note "third-party notice index matches the repository"
fi

note "installing $deb"
dpkg -i "$deb" >"$work/dpkg-install.log" 2>&1 \
    || { tail -20 "$work/dpkg-install.log" >&2; die "dpkg -i failed"; }
for path in /usr/bin/nekobox /usr/libexec/Iblis/nekobox \
            /usr/libexec/Iblis/nekobox_core; do
    [ -e "$path" ] || die "package is missing $path"
    [ -x "$path" ] || die "$path is not executable"
done

note "checking the packaged core"
core_output=$(/usr/libexec/Iblis/nekobox_core version 2>&1) \
    || { printf '%s\n' "$core_output" >&2; die "core failed to run"; }
first_line=${core_output%%$'\n'*}
printf '%s\n' "$first_line"
grep -q '^sing-box version ' <<<"$core_output" \
    || die "core did not print a sing-box version"

note "checking the GUI and its live core child"
mkdir -p "$profile/home" "$profile/config" "$profile/runtime" "$appdata"
chmod 700 "$profile/runtime"
HOME=$profile/home \
XDG_CONFIG_HOME=$profile/config \
XDG_RUNTIME_DIR=$profile/runtime \
QT_QPA_PLATFORM=offscreen \
    setsid /usr/bin/nekobox "$appdata" >"$gui_log" 2>&1 &
launcher_pid=$!
disown "$launcher_pid" 2>/dev/null || true

deadline=$((SECONDS + 30))
while [ "$SECONDS" -lt "$deadline" ]; do
    gui_pid=$(find_gui || true)
    [ -n "$gui_pid" ] && break
    sleep 0.5
done
if [ -z "$gui_pid" ]; then
    tail -60 "$gui_log" >&2 || true
    dump_processes
    die "GUI did not start with appdata $appdata"
fi
note "GUI pid $gui_pid"

deadline=$((SECONDS + 30))
while [ "$SECONDS" -lt "$deadline" ]; do
    core_pid=$(find_core || true)
    [ -n "$core_pid" ] && break
    if ! kill -0 "$gui_pid" 2>/dev/null; then
        tail -60 "$gui_log" >&2 || true
        dump_processes
        die "GUI pid $gui_pid exited before spawning its core"
    fi
    sleep 0.5
done
if [ -z "$core_pid" ]; then
    tail -60 "$gui_log" >&2 || true
    dump_processes
    die "GUI pid $gui_pid did not spawn /usr/libexec/Iblis/nekobox_core -waitpid $gui_pid"
fi
note "GUI spawned core pid $core_pid (-waitpid $gui_pid)"

sleep 12
live_gui=$(find_gui || true)
if [ "$live_gui" != "$gui_pid" ]; then
    tail -60 "$gui_log" >&2 || true
    dump_processes
    die "GUI did not remain alive for 12s (started $gui_pid, now ${live_gui:-none})"
fi
live_core=$(find_core || true)
if [ -z "$live_core" ]; then
    tail -60 "$gui_log" >&2 || true
    dump_processes
    die "GUI's core child did not remain alive for 12s"
fi
core_pid=$live_core
note "GUI and its core child stayed alive for 12s"

note "package smoke test passed${series:+ for $series}"
