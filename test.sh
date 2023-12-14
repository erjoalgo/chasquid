#!/bin/bash -x

set -euo pipefail

cd "$(realpath $(dirname "${BASH_SOURCE[0]}"))"

EXTRA_ARGS=()

while getopts "u:m:t:f:s:b:p:kh" OPT; do
    case ${OPT} in
    u)
        SMTP_USER=${OPTARG}
        # including domain
        ;;
    m)
        SMTP_HOST=${OPTARG}
        ;;
    t)
        TO_EMAILS=${OPTARG}
        ;;
    # optional
    k)
        EXTRA_ARGS+="--tls-certcheck=off"
        ;;
    s)
        SUBJECT=${OPTARG}
        ;;
    b)
        BODY=${OPTARG}
        ;;
    h)
        less $0
        exit 0
        ;;
    esac
done
shift $((OPTIND -1))

PORT=${PORT:-465}
SUBJECT=${SUBJECT:-chasquid test email}
BODY=${BODY:-hola hola}

if ! command -v msmtp; then
    sudo apt-get install -y msmtp
fi

FULL_NAME=$(getent passwd ${USER} | cut -d: -f5 | cut -d, -f1)

CONTENTS=$(cat <<EOF
From: ${FULL_NAME} <${SMTP_USER}>
To: ${TO_EMAILS}
Subject: ${SUBJECT}

${BODY}
EOF
)

tee /dev/stderr <<< "${CONTENTS}" | \
    msmtp -d --host=${SMTP_HOST} --auth=plain --tls=on  \
      --port=${PORT} --user ${SMTP_USER} \
      --read-envelope-from --read-recipients --tls-starttls=off \
      ${EXTRA_ARGS[@]}
