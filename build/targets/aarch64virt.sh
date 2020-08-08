#!/bin/bash

. ${CROOT}/build/targets/aarch64.inc

aexport PLATFORM=aarch64virt
aexport IMAGE_LOAD=0x40080000

