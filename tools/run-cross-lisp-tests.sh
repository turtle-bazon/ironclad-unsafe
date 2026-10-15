#!/bin/sh
# Run Ironclad tests on locally installed Lisp implementations.
#
# Examples:
#
#   # Full suite on all locally available Lisps:
#   tools/run-cross-lisp-tests.sh
#
#   # Select implementations:
#   LISPS='sbcl-bin ecl' tools/run-cross-lisp-tests.sh
#   tools/run-cross-lisp-tests.sh sbcl-bin ecl
#
#   # Run only selected Ironclad tests:
#   IRONCLAD_TESTS='sha512/256' tools/run-cross-lisp-tests.sh sbcl-bin
#   tools/run-cross-lisp-tests.sh ecl mceliece
#
#   # List available test names:
#   tools/run-cross-lisp-tests.sh --list
#
# Roswell can install the free Lisps without root, for example:
#   ros install sbcl-bin
#   ros install ccl-bin/1.13
#   ros install ecl
#   ros install abcl-bin/1.9.3
#
# Allegro Express is also usable locally through Roswell:
#   ros install allegro/11.0express
#
# CLISP is intentionally excluded because the Quicklisp bordeaux-threads
# release does not support it and Ironclad depends on bordeaux-threads.
# LispWorks remains supported in the source tree, but is intentionally not
# installed or tested here.
set -u

DEFAULT_LISPS='sbcl-bin ccl-bin ecl abcl-bin allegro/11.0express'
LISPS="${LISPS:-$DEFAULT_LISPS}"
SELECTED_TESTS="${IRONCLAD_TESTS:-}"
LIST_TESTS=0
POSITIONAL_LISPS=''

usage() {
    sed -n '3,30p' "$0"
}

for arg in "$@"; do
    case "$arg" in
        --help|-h)
            usage
            exit 0
            ;;
        --list|-l)
            LIST_TESTS=1
            ;;
        sbcl-bin|ccl-bin|ecl|abcl-bin|allegro|allegro/11.0express)
            POSITIONAL_LISPS="$POSITIONAL_LISPS $arg"
            ;;
        *)
            SELECTED_TESTS="$SELECTED_TESTS $arg"
            ;;
    esac
done

if [ -n "$POSITIONAL_LISPS" ]; then
    # Trim the leading space added by the loop above.
    LISPS="${POSITIONAL_LISPS# }"
fi

export IRONCLAD_TESTS="${SELECTED_TESTS# }"

export PATH="$HOME/.roswell/bin:$HOME/.local/bin:$PATH"

if ! command -v ros >/dev/null 2>&1; then
    echo "Roswell not found in PATH; install it first:"
    echo "  curl -L https://raw.githubusercontent.com/roswell/roswell/master/scripts/install-for-ci.sh | sh"
    exit 1
fi

cd "$(dirname "$0")/.." || exit 1

RUNNER="$(pwd)/tools/run-selected-tests.lisp"

safe_lisp() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-'
}

if [ "$LIST_TESTS" -eq 1 ]; then
    LIST_LISP="${LIST_LISP:-sbcl-bin}"
    IRONCLAD_TEST_ACTION=list
    export IRONCLAD_TEST_ACTION
    log="/tmp/ironclad-list-tests.log"
    timeout "${IRONCLAD_TEST_TIMEOUT:-14400}" ros -L "$LIST_LISP" \
        -e '(ql:quickload (list "bordeaux-threads" "rt"))' \
        -e "(push #p\"$(pwd)/\" asdf:*central-registry*)" \
        -e '(asdf:load-system :ironclad/tests)' \
        -l "$RUNNER" \
        --quit > "$log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        grep -a . "$log"
        exit 0
    fi
    echo "Failed to list tests (rc=$rc, log=$log)"
    exit "$rc"
fi

for lisp in $LISPS; do
    log="/tmp/ironclad-$(safe_lisp "$lisp").log"
    echo "=== $lisp ==="
    if [ -n "$IRONCLAD_TESTS" ]; then
        echo "Selected tests: $IRONCLAD_TESTS"
    fi
    start=$(date +%s)
    timeout "${IRONCLAD_TEST_TIMEOUT:-14400}" ros -L "$lisp" \
        -e '(ql:quickload (list "bordeaux-threads" "rt"))' \
        -e "(push #p\"$(pwd)/\" asdf:*central-registry*)" \
        -e '(asdf:load-system :ironclad/tests)' \
        -l "$RUNNER" \
        --quit > "$log" 2>&1
    rc=$?
    end=$(date +%s)
    if grep -aq "IRONCLAD-TEST-STATUS: PASS" "$log"; then
        echo "$lisp: PASS (rc=$rc, $((end - start))s, log=$log)"
    elif grep -aq "IRONCLAD-TEST-STATUS: FAIL" "$log"; then
        echo "$lisp: FAIL (rc=$rc, $((end - start))s, log=$log)"
    elif [ "$rc" -eq 0 ]; then
        echo "$lisp: FINISHED WITHOUT TEST STATUS (rc=$rc, $((end - start))s, log=$log)"
    else
        echo "$lisp: FAIL/TIMEOUT (rc=$rc, $((end - start))s, log=$log)"
    fi
done
