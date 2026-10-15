#!/bin/sh
# Run the Ironclad test suite on the locally installed free Lisps.
#
# Roswell installs them without root, for example:
#   ros install sbcl-bin
#   ros install ccl-bin/1.13
#   ros install ecl
#   ros install clisp/2.49
#   ros install abcl-bin/1.9.3
#
# Allegro CL and LispWorks are proprietary, so they are intentionally not
# auto-installed here.  Install them manually, then add their Roswell names
# to LISPS when they are available locally.
set -u

LISPS="${LISPS:-sbcl-bin ccl-bin ecl clisp abcl-bin}"
export PATH="$HOME/.roswell/bin:$HOME/.local/bin:$PATH"

if ! command -v ros >/dev/null 2>&1; then
    echo "Roswell not found in PATH; install it first:"
    echo "  curl -L https://raw.githubusercontent.com/roswell/roswell/master/scripts/install-for-ci.sh | sh"
    exit 1
fi

cd "$(dirname "$0")/.." || exit 1

for lisp in $LISPS; do
    log="/tmp/ironclad-${lisp}.log"
    echo "=== $lisp ==="
    start=$(date +%s)
    timeout "${IRONCLAD_TEST_TIMEOUT:-14400}" ros -L "$lisp" \
        -e '(ql:quickload (list "bordeaux-threads" "rt"))' \
        -e "(push #p\"$(pwd)/\" asdf:*central-registry*)" \
        -e '(asdf:load-system :ironclad/tests)' \
        -e '(unless (rt:do-tests) (uiop:quit -1))' \
        --quit > "$log" 2>&1
    rc=$?
    end=$(date +%s)
    if grep -q "No tests failed." "$log"; then
        echo "$lisp: PASS (rc=$rc, $((end - start))s, log=$log)"
    elif [ "$rc" -eq 0 ]; then
        echo "$lisp: FINISHED WITHOUT SUMMARY (rc=$rc, $((end - start))s, log=$log)"
    else
        echo "$lisp: FAIL (rc=$rc, $((end - start))s, log=$log)"
    fi
done
