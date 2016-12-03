#!/bin/bash -x

LIO_CFGFS="/sys/kernel/config/target/"
FILE_LU_HW_BLOCK_SIZE=512

FABRIC_UUID=`uuidgen |sed "s#.*-##g"`
LU_UUID=`uuidgen |sed "s#.*-##g"`

function _usage {
	echo "usage: $0 -l <lun> -n <name> -p <elasto_path> -K <azure_key> -s <size>"
	exit 1
}

function _fatal {
	echo "fatal: $*"
	exit 1
}

lun=0
lu_name=""
elasto_path=""
azure_acc_key=""
lu_size=""
while getopts ":l:n:p:K:s:" o; do
	case "${o}" in
	l)
		lun=${OPTARG}
		;;
	n)
		lu_name=${OPTARG}
		;;
	p)
		elasto_path=${OPTARG}
		;;
	K)
		azure_acc_key=${OPTARG}
		;;
	s)
		lu_size=${OPTARG}
		;;
	*)
		_usage
		;;
	esac
done
shift $((OPTIND - 1))
[ -z "$1" ] || _usage

modprobe target_core_user tcm_loop || _fatal "failed to load LIO kernel modules"

[ -d $LIO_CFGFS ] \
	|| _fatal "$LIO_CFGFS not present - LIO kernel modules not loaded?"
mkdir -p ${LIO_CFGFS}/core/user_0/${lu_name} \
	||  _fatal "failed to create tcmu backstore"
if [ -z "${azure_acc_key}" ]; then
	# could be a local FS (test back-end) URI (no access key needed)
	echo "dev_config=elasto/${elasto_path}" \
				> ${LIO_CFGFS}/core/user_0/${lu_name}/control \
				|| _fatal "LIO control file I/O failed"
else
	echo "dev_config=elasto/${elasto_path} ${azure_acc_key}" \
				> ${LIO_CFGFS}/core/user_0/${lu_name}/control \
				|| _fatal "LIO control file I/O failed"
fi
echo "dev_size=${lu_size}" \
			> ${LIO_CFGFS}/core/user_0/${lu_name}/control \
			|| _fatal "LIO control file I/O failed"
echo "hw_block_size=${FILE_LU_HW_BLOCK_SIZE}" \
			> ${LIO_CFGFS}/core/user_0/${lu_name}/control \
			|| _fatal "LIO control file I/O failed"
echo 1 > ${LIO_CFGFS}/core/user_0/${lu_name}/enable \
	|| _fatal "failed to enable ${lu_name}"

# loopback fabric
mkdir -p ${LIO_CFGFS}/loopback/naa.${FABRIC_UUID}/tpgt_0/lun/lun_${lun} \
	||  _fatal "failed to create LUN for tcmu backstore"
echo $NEXUS_UUID > ${LIO_CFGFS}/loopback/naa.${FABRIC_UUID}/tpgt_0/nexus \
cd loopback/naa.${FABRIC_UUID}/tpgt_0/lun/lun_${lun} \
	|| _fatal "failed to enter lun dir"
ln -s ${LIO_CFGFS}/core/user_0/${lu_name}/ \
	${LIO_CFGFS}/loopback/naa.${FABRIC_UUID}/tpgt_0/lun/lun_${lun}/${LU_UUID} \
	|| _fatal "failed to create lun symlink"
