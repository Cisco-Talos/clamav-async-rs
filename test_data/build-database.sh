#!/usr/bin/env bash

testDir="/tmp/rust-clam-av-testing"
testDataDir=$(pwd)

install -d "${testDir}"
pushd "${testDir}"
echo testing > COPYING
sigtool --md5 "${testDataDir}/files/naughty_file" > example.hdb
install -d out

SIGNDUSER=me sigtool --unsigned --datadir=. --build=example.cud --max-bad-sigs 0 --cvd-version 1

cp example.cud "${testDataDir}/database"
popd