#!/usr/bin/env bash
#
# Copyright (c) 2014 Christian Couder
# MIT Licensed; see the LICENSE file in this repository.
#

test_description="Test mount command"

. lib/test-lib.sh

# if in travis CI, don't test mount (no fuse)
if ! test_have_prereq FUSE; then
  skip_all='skipping mount tests, fuse not available'

  test_done
fi


export IPFS_NS_MAP="welcome.example.com:/ipfs/$HASH_WELCOME_DOCS"

# start iptb + wait for peering
NUM_NODES=5
test_expect_success 'init iptb' '
  iptb testbed create -type localipfs -count $NUM_NODES -init
'
startup_cluster $NUM_NODES

# test mount failure before mounting properly.
test_expect_success "'ipfs mount' fails when there is no mount dir" '
  tmp_ipfs_mount() { ipfsi 0 mount -f=not_ipfs -n=not_ipns >output 2>output.err; } &&
  test_must_fail tmp_ipfs_mount
'

test_expect_success "'ipfs mount' output looks good" '
  test_must_be_empty output &&
  test_should_contain "not_ipns\|not_ipfs" output.err
'

test_expect_success "setup and publish default IPNS value" '
  mkdir "$(pwd)/ipfs" "$(pwd)/ipns" &&
  ipfsi 0 name publish QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn
'

# make sure stuff is unmounted first
# then mount properly
test_expect_success FUSE "'ipfs mount' succeeds" '
  do_umount "$(pwd)/ipfs" || true &&
  do_umount "$(pwd)/ipns" || true &&
  ipfsi 0 mount -f "$(pwd)/ipfs" -n "$(pwd)/ipns" >actual
'

test_expect_success FUSE "'ipfs mount' output looks good" '
  echo "IPFS mounted at: $(pwd)/ipfs" >expected &&
  echo "IPNS mounted at: $(pwd)/ipns" >>expected &&
  test_cmp expected actual
'

test_expect_success FUSE "local symlink works" '
  ipfsi 0 id -f"<id>\n" > expected &&
  basename $(readlink ipns/local) > actual &&
  test_cmp expected actual
'

test_expect_success FUSE "can resolve ipns names" '
  echo -n "ipfs" > expected &&
  cat ipns/welcome.example.com/ping > actual &&
  test_cmp expected actual
'

test_expect_success "mount directories cannot be removed while active" '
  test_must_fail rmdir ipfs ipns 2>/dev/null
'

test_expect_success "unmount directories" '
  do_umount "$(pwd)/ipfs" &&
  do_umount "$(pwd)/ipns"
'

test_expect_success "mount directories can be removed after shutdown" '
  rmdir ipfs ipns
'

test_expect_success 'stop iptb' '
  iptb stop
'

test_done
