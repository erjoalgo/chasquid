#!/bin/bash -x

set -euo pipefail

cd "$(realpath $(dirname "${BASH_SOURCE[0]}"))"

go build

ROOT=$(pwd)/etc/chasquid
DOMAIN=example.com

# rm -rf ${ROOT}/certs
DOMAIN=erjoalgo.com

if ! test -e ${ROOT}/certs/${DOMAIN}/fullchain.pem; then
    unlink ${ROOT}/certs || true
    mkdir -p ${ROOT}/{domains,certs}/${DOMAIN}
    pushd .
    cd ${ROOT}/certs/${DOMAIN}
    # openssl genrsa > privkey.pem
    openssl req -newkey rsa:2048 -nodes -keyout privkey.pem -x509 \
            -days 365 -out fullchain.pem \
            -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=${DOMAIN}"
    popd
fi

cat<<EOF > ${ROOT}/chasquid.conf
submission_over_tls_address: ":465"
data_dir: "/tmp/chasquid"
dovecot_auth: true
EOF

sudo apt-get install -y dovecot-lmtpd dovecot-imapd \
     dovecot-pop3d dovecot-sieve dovecot-managesieved

pkill chasquid || true

# sudo chmod a+rw /var/run/dovecot/auth-{userdb,client}

sudo ./chasquid -alsologtostderr -config_dir ${ROOT}
