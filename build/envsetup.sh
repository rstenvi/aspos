#!/bin/bash 

function aexport()	{
	# Use file in $CROOT if variable has been defined, otherwise use current dir
	fname="aspos.env"
	if [ ! -z ${CROOT+x} ]; then
		fname="${CROOT}/aspos.env"
	fi

	# Remove entry if name already exist
	varname=$(echo $1|cut -d"=" -f1)
	sed -i "/^${varname}=.*/d" ${fname}


	echo "$1" >> ${fname}
	export $1
}

unset CROOT

# Clear and create file
> aspos.env


aexport CROOT=$(pwd)
aexport QEMU_PREFIX=~/local/qemu
aexport QEMU_BUILD=~/buildsrc/qemu
aexport QEMU_VERSION=stable-4.1
aexport JOBS=$(nproc)


function set_qemu_arch()	{
	aexport QARCH="${ARCH}"

	# QARCH and ARCH might be different in the future
}

function check_docker()	{
	docker ps >/dev/null
	if [[ "$?" -ne "0" ]]; then
		echo "[-] Unable to contact docker"
		echo "    Is daemon running?"
		echo "    Is docker accessible to current user?"
		echo "    To use docker as non-root user, do: sudo usermod -aG docker $USER"
		return 1
	fi
	return 0
}

function check_compiler()	{
	if ! docker images | grep "${DOCKERNAME}" >/dev/null; then
		echo "[-] No matching image found for ${DOCKERNAME}, create with"
		echo "build compiler"
		return
	fi
	echo "[+] Docker image with tag ${DOCKERNAME} is present, compilation can be performed"
}

function check_qemu()	{
	set_qemu_arch
	which qemu-system-${QARCH} >/dev/null
	if [[ "$?" -ne "0" ]]; then
		echo "No working qemu emulator for target: ${QARCH} found"
		return 1
	fi
	echo "Running following qemu version"
	qemu-system-${QARCH} --version
}


function check()	{
	check_docker
	if [[ "$?" -eq "0" ]]; then
		check_compiler
	fi
	check_qemu
}

function build_compiler()	{
	echo "This is going to take a while..."
	pushd ${CROOT}/docker/os
	docker build --build-arg TARGET=${TARGET} -t ${DOCKERNAME} .
	popd
}

function update_compiler() {
	docker tag ${DOCKERNAME} ${DOCKERNAME}-backup
	docker pull ubuntu:20.04
	build_compiler
	echo "If new compiler is working, you should delete old image: ${DOCKERNAME}-backup"
}

function build_qemu()	{
	mkdir -p ${QEMU_PREFIX}
	mkdir -p ${QEMU_BUILD}

	# Must download if it doesn't exist
	if [ ! -d ${QEMU_BUILD}/qemu ]; then
		pushd ${QEMU_BUILD} >/dev/null
		git clone https://git.qemu.org/git/qemu.git
		cd qemu
		git checkout ${QEMU_VERSION}
		git submodule init
	else
		pushd ${QEMU_BUILD}/qemu >/dev/null
	fi

	# We are in qemu-dir now and:
	# - We might be doing first configure and make, or
	# - we might be doing an updated build of a new version
	git submodule update --recursive
	./configure --enable-debug --enable-debug-info --prefix=${QEMU_PREFIX} && make -j${JOBS} && make install

	if [[ "$?" -eq "0" ]]; then
		echo "Build of qemu finished"
		echo "You must now add ${QEMU_PREFIX}/bin to the path"
		echo "export PATH=${QEMU_PREFIX}/bin:\$PATH"
	else
		echo "Something went wrong with the build, check qemu log"
	fi
	popd >/dev/null

}

function build()	{
	if [[ "$#" -ne "1" ]]; then
		echo "Valid builds"
		echo "    compiler"
		echo "    qemu"
		echo "    qemu-prereqs-ubuntu"
		echo ""
		return 1
	fi
	case $1 in
		compiler)
			build_compiler
			;;
		qemu)
			build_qemu
			;;
		qemu-prereqs-ubuntu)
			# Based on: https://wiki.qemu.org/Hosts/Linux
			sudo apt-get install -y git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev
			;;
		*)
			echo "${1} is not a valid build command"
			return 1
			;;
	esac
	return 0
}

function dump()	{
	if [[ "$#" -ne "1" ]]; then
		echo "Valid dump-commands"
		printf "    exports\n"
		echo ""
		return 1
	fi
	case $1 in
		exports)
			cat ${CROOT}/aspos.env
			;;
		*)
			echo "${1} is not a valid dump command"
			return 1
			;;
	esac
	return 0
}



function lunch()	{
	if [[ "$#" -ne "1" ]]; then
		echo "Valid targets"
		pushd ${CROOT}/build/targets >/dev/null
		ls *.sh | while read line; do
			target=$(echo $line | sed 's/.sh//g')
			printf "    $target\n"
		done
		popd >/dev/null
	else
		FILE="${CROOT}/build/targets/${1}.sh"
		if test -f "$FILE"; then
			. ${FILE}
			if [ -z ${PLATFORM+x} ]; then
				echo "PLATFORM must be set by initialization script for target"
				return 1
			fi
			if [ -z ${ARCH+x} ]; then
				echo "ARCH must be set by initialization script for target"
				return 1
			fi
			check
			echo 
			cat ${CROOT}/aspos.env
			echo 
		else
			echo "${FILE} was not found, is ${1} a valid target?"
		fi
	fi

}



function mm()	{
	if [ -z ${PLATFORM+x} ]; then
		echo "PLATFORM must be set, run lunch"
		return 1
	fi

	# -v ${CROOT}/src/libaspos.a:/opt/cross/${TARGET}/lib/libasos.a
	docker run --rm --env-file ${CROOT}/aspos.env -v ${CROOT}:${CROOT} -w ${CROOT}/$(realpath --relative-to=${CROOT} .) ${DOCKERNAME} make ${@}
}

# This function is meant to simulate the compiler which will eventually be built
# for user-mode programs. The user mode library is changed often and it's
# quicker to mount the necessary files as volumes, as opposed to building a
# separate image user-mode compiler.
function mu() {
	if [ -z ${PLATFORM+x} ]; then
		echo "PLATFORM must be set, run lunch"
		return 1
	fi

	LIBVOL="-v ${CROOT}/src/libaspos.a:/opt/cross/${TARGET}/lib/libaspos.a"
	LINKVOL="-v ${CROOT}/src/userlib/linker-${TARGET}.ld:/opt/cross/${TARGET}/lib/aspos-user.ld"
	CRTVOL="-v ${CROOT}/src/userlib/crt0.o:/opt/cross/${TARGET}/lib/crt0.o"
	INCVOL="-v ${CROOT}/src/include/lib.h:/opt/cross/${TARGET}/${TARGET}/include/aspos.h"

	docker run --rm --env-file ${CROOT}/aspos.env -v ${CROOT}:${CROOT} ${LINKVOL} ${INCVOL} ${CRTVOL} ${LIBVOL} -w ${CROOT}/src/apps ${DOCKERNAME} make ${@}
}

function m()	{
	if [ -z ${PLATFORM+x} ]; then
		echo "PLATFORM must be set, run lunch"
		return 1
	fi
	docker run --rm --env-file ${CROOT}/aspos.env -v ${CROOT}:${CROOT} -w ${CROOT} ${DOCKERNAME} make ${@}
}


function croot()  { cd ${CROOT}; }
function carch()  { cd ${CROOT}/src/arch/${ARCH}; }
function ckernel()   { cd ${CROOT}/src/kernel; }

function describe() {
	if [[ "$#" -lt "1" ]]; then
		${CROOT}/scripts/config/config.py describe
	else
		${CROOT}/scripts/config/config.py describe -i $1
	fi
}

