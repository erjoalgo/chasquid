#!/bin/bash -x

set -euo pipefail

cd "$(realpath $(dirname "${BASH_SOURCE[0]}"))"

while getopts "e:p:h:" OPT; do
    case ${OPT} in
    e)
        EMAIL=${OPTARG}
        ;;
    p)
        PASSWORD=${OPTARG}
        ;;
    h)
        less $0
        exit 0
        ;;
    esac
done
shift $((OPTIND -1))

PASSDB=/etc/dovecot/passwd

sudo insert-text-block \
     '# 1f383549-b927-4d4c-9bc7-51ddc0628929-dovecot-add-passdb' \
     /etc/dovecot/dovecot.conf <<EOF
passdb {
  driver = passwd-file
  args = ${PASSDB}
}
EOF

ENCPASS=$(doveadm pw -u "${EMAIL}" -p "${PASSWORD}")
if test -e "${PASSDB}"; then
    sudo sed --in-place=.old "/^${EMAIL}:/d" "${PASSDB}"
fi

sudo tee -a "${PASSDB}" <<< "${EMAIL}:${ENCPASS}::::"
echo "${EMAIL} added to ${PASSDB}"

for _ in $(seq 3); do
    if ./cmd/dovecot-auth-cli/dovecot-auth-cli  \
           /var/run/dovecot/auth auth "${EMAIL}" "${PASSWORD}" | grep yes; then
        break
    fi
    sudo service dovecot stop
    sleep 1
    sudo service dovecot start
done
