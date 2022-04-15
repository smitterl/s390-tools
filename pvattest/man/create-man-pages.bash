#!/bin/bash
set -u

PVATTEST="../pvattest"

#TODO fence measure

CMD_PVATTEST="${PVATTEST}"
CMD_CREATE="${PVATTEST} create"
CMD_MEASURE="${PVATTEST} measure"
CMD_VERIFY="${PVATTEST} verify"

TMP_FILE="tmp.help"
CPR_FILE="man-copyright"

function convert_command {
	command=$1
	basename "${command}" | sed -e 's/ /-/'
}

function gen_man {
	command=$1
	name="$(convert_command "${command}")"

	echo " generating ${name}.8"

	# the help output uses other keywords and different style than man pages.
	${command} -h | sed -e 's/Usage:/NAME/g' -e 's/Commands:/SYNOPSIS/g' -e 's/Description:/DESCRIPTION/g' -e 's/Help Options:/OPTIONS/g' -e '/Application Options:/d' -e 's/Example:/EXAMPLE/g' -e 's/^  //g' > ${TMP_FILE}
	# remove newlines inside the same paragraph (see parse.c)
	sed -i -e ':a;N;s/ \n */ /;ta;P;D' "${TMP_FILE}"


	# add "see also" section with references to the other commands
	echo "SEE ALSO" >> "${TMP_FILE}"
	delim=""
	for e in "${ALL_NAMES[@]}"; do
		[[ "${e}" == "${name}" ]] && continue;
		printf "%s(8)" "$delim${e}" >> "${TMP_FILE}"
		delim=", "
	done
	#add copyright note
	cp "${CPR_FILE}" "${name}.8"
	# generate the man file; while we are at it set the default formatting: no hyphenation(.nh) and only left justification (.ad d)
	txt2man -t "${name}" -s 8 -B "FILE"  -r "s390-tools" -v "Attestation Manual" ${TMP_FILE} | sed -e '/\.TH.*/a .nh\n.ad l' | tail -n +2 >> "${name}".8
}

ALL_NAMES=("$(convert_command "${CMD_PVATTEST}")" "$(convert_command "${CMD_CREATE}")" "$(convert_command "${CMD_VERIFY}")")

#only generate man file if the compiled program supports the measurement (S390X only)
if "${PVATTEST}" -h |grep -q "$(echo ${CMD_MEASURE}| sed -e ' s/\.\.\///')"; then
	gen_man "${CMD_MEASURE}"
	ALL_NAMES[4]="$(convert_command "${CMD_MEASURE}")"
fi

gen_man "${CMD_CREATE}"
gen_man "${CMD_VERIFY}"
gen_man "${CMD_PVATTEST}"

rm "${TMP_FILE}"
