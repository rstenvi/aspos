#!/bin/bash

# Common variables which can be used in any aarch64 target

aexport ARCH=aarch64
aexport TARGET=aarch64-none-elf
aexport ARCH_LITTLE_ENDIAN=1
aexport ARCH_CPUBITS=64

# Dockerfile which can be used to build the compiler
# Along with TARGET, this should be enough info to build compiler
# Childs of this file can override it to specify a different Dockerfile
aexport DOCKERFILE=Dockerfile.lwip

aexport DOCKERNAME=compiler-aarch64-lwip

