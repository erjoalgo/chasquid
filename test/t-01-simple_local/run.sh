#!/bin/bash

set -e
. $(dirname ${0})/../util/lib.sh

init

generate_certs_for testserver
add_user user@testserver secretpassword
add_user someone@testserver secretpassword

mkdir -p .logs
chasquid -v=2 --logfile=.logs/chasquid.log --config_dir=config &
wait_until_ready 1025

run_msmtp someone@testserver < content

wait_for_file .mail/someone@testserver

mail_diff content .mail/someone@testserver

# At least for now, we allow AUTH over the SMTP port to avoid unnecessary
# complexity, so we expect it to work.
if ! run_msmtp -a smtpport someone@testserver < content 2> /dev/null; then
	fail "failed auth on the SMTP port"
fi

if run_msmtp nobody@testserver < content 2> /dev/null; then
	fail "successfuly sent an email to a non-existent user"
fi

if run_msmtp -a baduser someone@testserver < content 2> /dev/null; then
	fail "successfully sent an email with a bad password"
fi

if run_msmtp -a badpasswd someone@testserver < content 2> /dev/null; then
	fail "successfully sent an email with a bad password"
fi

success
