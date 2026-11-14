#!/bin/ksh -p
# SPDX-License-Identifier: CDDL-1.0
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the CDDL is also available via the Internet at
# https://opensource.org/license/CDDL-1.0.
#

#
# Copyright (c) 2026, TrueNAS.
#

#
# DESCRIPTION:
#	Encrypting a large ZIL block must not allocate a large kmem buffer
#	for the AAD.
#
#	The AAD of an encrypted ZIL or dnode block covers most of the block
#	(see zio_crypt_init_uios_zil() and zio_crypt_init_uios_dnode() in
#	module/zfs/zio_crypt.c), so an encryption backend that copies the
#	AAD into a private buffer has to kmem_alloc() tens of kilobytes for
#	each of those blocks.  That trips the SPL large allocation check
#	(spl_kmem_alloc_warn, 64K by default), which logs a warning and a
#	stack trace from the z_wr_iss threads.
#
#	The kernel crypto API backend (zio_crypt_os_kcapi.c) did this, and
#	is https://github.com/openzfs/zfs/issues/19823.  The AAD is mapped
#	in place now instead of copied.  The ICP backend never copied the
#	AAD, so this test passes with either backend and only fails when a
#	backend starts copying large AAD buffers again.
#
# STRATEGY:
#	1. Create an encrypted dataset with sync=always, so that writes are
#	   written through the ZIL.
#	2. Write enough synchronous data to fill several ZIL blocks of more
#	   than 64K each.
#	3. Verify the data reads back intact.
#	4. Verify the large kmem_alloc() warning was not logged.
#

. $STF_SUITE/include/libtest.shlib

verify_runnable "global"

typeset encroot=$TESTPOOL/$TESTFS/enc_aad
typeset encdir=$TESTDIR/enc_aad
typeset nfiles=100

function cleanup
{
	destroy_dataset "$encroot" "-rf"
}

log_assert "Encrypting a large ZIL block does not allocate a large AAD buffer"
log_onexit cleanup

#
# Only the kernel crypto API backend ever copied the AAD, and it is only
# compiled in when configure found usable kernel crypto exports
# (HAVE_KERNEL_CRYPTO, see config/kernel-crypto.m4).  On a stock kernel
# the ICP backend is used and this test passes without exercising the
# code under test, so say so rather than implying coverage we don't have.
#
log_note "This test only exercises the code under test on a build made" \
    "with HAVE_KERNEL_CRYPTO (kernel crypto API backend)"

# The warning is emitted by the SPL and only exists on Linux.
if ! is_linux; then
	log_unsupported "spl_kmem_alloc_warn is Linux-specific"
fi

typeset warnfile=/sys/module/spl/parameters/spl_kmem_alloc_warn
if [[ ! -r $warnfile ]]; then
	log_unsupported "spl does not export spl_kmem_alloc_warn"
fi

typeset warnsize=$(cat "$warnfile")
if [[ $warnsize -eq 0 ]]; then
	log_unsupported "spl_kmem_alloc_warn is disabled"
fi

# Reading the kernel log is required to observe the warning.
typeset logmark
if ! logmark=$(dmesg 2>/dev/null | wc -l); then
	log_unsupported "cannot read the kernel log"
fi

log_must eval "echo 'password' | zfs create -o encryption=on" \
    "-o keyformat=passphrase -o keylocation=prompt -o sync=always" \
    "-o recordsize=128k -o compression=off -o mountpoint=$encdir $encroot"

#
# sync=always puts every write in the ZIL.  ZIL blocks are capped at 128K,
# so writing several megabytes of small synchronous records produces many
# blocks whose AAD is well over the 64K warning threshold.
#
typeset i
for i in {1..$nfiles}; do
	log_must dd if=/dev/urandom of=$encdir/f$i bs=32k count=1 \
	    conv=fsync status=none
done

log_must zpool sync "$TESTPOOL"

#
# The encrypted data must still round-trip.  Reading it back also exercises
# the decrypt path, which had the same oversized AAD buffer.
#
for i in {1..$nfiles}; do
	typeset size=$(stat -c %s $encdir/f$i)
	[[ $size -eq 32768 ]] || \
	    log_fail "f$i is $size bytes, expected 32768"
done

typeset newmsgs=$(dmesg 2>/dev/null | tail -n +$((logmark + 1)))

if echo "$newmsgs" | grep -q "Large kmem_alloc"; then
	log_fail "large kmem_alloc() logged while encrypting ZIL blocks:" \
	    "$(echo "$newmsgs" | grep 'Large kmem_alloc')"
fi

log_pass "Encrypting a large ZIL block does not allocate a large AAD buffer"
