# aspos

## Current status

In development and unstable.

## Setting up build environment

The following commands set up several commands and environmental variables.

~~~
$ . build/envsetup.sh
$ lunch aarch64virt
~~~

The cross compiler is in docker, so the docker image must be built.

~~~
$ build_compiler
~~~

## Generating config

Default configuration template can be generated with `defconfig`

~~~
$ make defconfig
~~~

You can now make changes to `kconfig.yaml` in root directory, when finished,
generate config.

~~~
$ make genconfig
~~~

The C header file should be written to `src/include/config.h`

## Building the code

Three aliases has been created to build the code:

~~~
$ m    # Build from root directory
$ mm   # Build from current directory
$ mu   # Build user-mode apps in src/apps/
~~~

The kernel must be built first, it should create the following files in the src
directory.

- `Image` - Kernel which can be booted
- `aspos.elf` - ELF of the kernel, useful if you want to debug in gdb
- `libaspos.a` - Archive which user mode programs can link against

When `libaspos.a` has been built, the user-mode programs can be built by typing
`mu`

## Running the kernel

The kernel can be tested in Qemu by typing the following in the src directory.

~~~
$ make run
~~~

