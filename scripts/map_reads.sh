#!/usr/bin/env bash

# map_reads_set.sh

# Clockwork equivalent in bash script to call instead of subprocess 
# defaults: 
set -euo pipefail

declare CLEANUP="no"
# arg vars
declare ref_fasta \
        reads1 \
        reads2 \
        outdir \
        outfile \
        prefix \
        suffix \
        par_tmpdir \
        tmpdir \
        rgid \
        rgsm \
        read_group \
        threads \
        mm2_preset \
        rmdup=false \
        markdup=false \
        verbose=false

# Other defaults:
#   threads: 1
#   minima2_preset: sr

# for flagged options (not positional)
declare -a minimap2_kws=(
    -a  # output as SAM
)
declare -a markdup_kws=(
    "VALIDATION_STRINGENCY=LENIENT"
)

declare PICARD_JAR="${PICARD_JAR:-/bioinf-tools/picard.jar}"

trap_cleanup () { 
    if [[ -e "${tmpdir:-}" && "${CLEANUP:-no}" == "yes" ]] ; then
        rm -rf "$tmpdir"
    fi
}
trap 'trap_cleanup' EXIT

# usage: check_unset VAR_NAME. Exits with code 2 if set
check_unset () {
    if [[ -z "${1+x}" ]] ; then
        echo "usage: check_unset VAR_NAME. Exits with code 2 if var is set"
        exit
    fi
    local -n var=$1
    if [[ -n "${var+x}" ]] ; then
        echo "More than one value for $1"
        exit 2
    fi
}

helpdoc () {
    cat <<-HELPDOC
usage: map_reads <--ref|> REF_FASTA <-1|--reads1|> READS1_FASTQ
            <-2|--reads2|> READS2_FASTQ <-O|--outdir> outdir
            [OPTIONS] [OTHER_MINIMAP2_OPTIONS]

Required
--------
<--ref>        FASTA    reference fasta. corresponds to target.fa
<-1|--reads1>  FASTQ    reads1 fastq or gzipped fq (forward reads)
<-2|--reads2>  FASTQ    reads2 fastq or gzipped fq (reverse reads)

Optional
--------
<-p|--prefix>  PREFIX   prefix with which to name output files. Default taken
                            from READS1 fastq
<--outfile>    FNAME    file name for output SAM/BAM
<-O|--outdir>  PATH     Output directory. Default current dir
--rmdup   <true|false>  Remove duplicates. Default false
--markdup <true|false>  Remove duplicates. Default false
--rg-id   ID            ID for SAM read group line
--rg-sm   NAME          SM (sample name) for SAM read group line
-t|--threads    INT     Number of threads to use. Default 1
-x|--mm2-preset STR     minimap2 preset. Default "sr". See minimap2 docs.
--tmpdir  PATH          Parent directory for temp files. Default outdir
-v|--verbose            Print verbose messages
-h|--help               Prints this help message

Additional arguments are passed to minimap2.

Notes
-----
-  If neither --rg-id nor --rg-sm are given, then no read group line is
   supplied to minimap2 (via -R option).
-  --rmdup and --markdup cannot both be true.

	HELPDOC
}

while (( $# >= 1 )) ; do
    case "$1" in
        -h|--help)       helpdoc && exit 0 ;;
        --ref)           check_unset ref_fasta && shift && ref_fasta="$1" ;;
        -1|--reads1)     check_unset reads1 && shift && reads1="$1" ;;
        -2|--reads2)     check_unset reads2 && shift && reads2="$1" ;;
        -O|--outdir)     check_unset outdir && shift && outdir="$1" ;;
        --tmpdir)        check_unset par_tmpdir && shift && par_tmpdir="$1" ;;
        -p|--prefix)     check_unset prefix && shift && prefix="$1" ;;
        --suffix)        check_unset prefix && shift && suffix="$1" ;;
        --rmdup)         rmdup=true ;;
        --markdup)       markdup=true ;;
        --rg-id)         check_unset rgid && shift && rgid="$1" ;;
        --rg-sm)         check_unset rgsm && shift && rgsm="$1" ;;
        -R)              check_unset read_group && shift && read_group="$1" ;;
        -t|--threads)    check_unset threads && shift && threads="$1" ;;
        -x|--mm2-preset) check_unset mm2_preset && shift && mm2_preset="$1" ;;
        --tmpdir)        check_unset tmpdir && shift && tmpdir="$1" ;;
        -v|--verbose)    verbose=true ;;
        *)               minimap2_kws+=("$1") ;;
    esac
    shift
done

#####  Check arguments  #####

# reference fasta (target for minimap2)
[[ -z "${ref_fasta:-}" ]] && ( echo "ERROR: No value for ref_fasta." >&2 && exit 2 ; )
[[ -f "$ref_fasta" ]] || ( echo "ERROR: Non-existent or not a file: $ref_fasta" >&2 && exit 2 ; )

# forward reads (query1)
[[ -z "${reads1:-}" ]] && ( echo "ERROR: No value for reads1." >&2 && exit 2 ; )
[[ -f "$reads1" ]] || ( echo "ERROR: Non-existent or not a file: $reads1" >&2 && exit 2 ; )

# reverse reads (query2)
[[ -z "${reads2:-}" ]] && ( echo "ERROR: No value for reads2." >&2 && exit 2 ; )
[[ -f "$reads2" ]] || ( echo "ERROR: Non-existent or not a file: $reads2" >&2 && exit 2 ; )

# output directory
[[ -z "${outdir=.}" ]] && ( echo "ERROR: --outdir given but is null" >&2 && exit 2 ; )

# prefix and suffix
if [[ -z "${prefix-x}" ]] ; then
    echo "ERROR: --prefix given but is null" >&2 && exit 2
elif [[ -z "${prefix+x}" ]] ; then
    prefix="$(basename "$reads1" | sed -E 's/^([A-Z]{3}[0-9]+)(_[12])?.*$/\1/')"
fi

suffix="${suffix:+.${suffix}}"

# threads are at least 1
(( ${threads=1} >= 1 )) || ( echo "ERROR: Bad value for --threads: $threads" >&2 && exit 2 ; )


# check that --rmdup and --markdup are not both true
[[ "$rmdup" == "true" && "$markdup" == "true" ]] && ( echo "ERROR: --rmdup and --markdup cannot both be true" >&2 && exit 2 ; )

# check and construct read_group line if indicated (for minimap2 sam)
if [[ -n "${rgid+x}" || -n "${rgsm+x}" ]] ; then

    # check that read_group is not also given
    [[ -z "${read_group+x}" ]] || (
        echo "ERROR: Cannot give both -R and --rg-id/--rg-sm" >&2 && exit 2)

    [[ -n "${rgid+x}" && -z "${rgid:-}" ]] && \
        echo "WARINING: --rgid given but is null (${rgid:-}) " >&2

    [[ -n "${rgsm+x}" && -z "${rgsm:-}" ]] && \
        echo "WARINING: --rg-sm given but is null (${rgsm:-}) " >&2
    
    read_group="@RG\tLB:LIB${rgid+\tID:}${rgid}${rgsm+\tSM:}${rgsm}"
    
elif [[ -n "${read_group+x}" && -z "${read_group:-}" ]] ; then
    echo "WARNING: -R given but is null (${read_group})" >&2
fi

minimap2_kws+=(
    -x "${mm2_preset=sr}"  # letting minimap2 do checks on --preset
    -t $(( threads > 1 ? threads - 1 : 1 ))  # reserve one thread for awk
)
[[ -n "${read_group-}" ]] && minimap2_kws+=(-R "$read_group")

### Set up output dirs and filepaths
[[ -e "$outdir" ]] || mkdir -p "$outdir"

tmpdir="$(mktemp -d -p "${par_tmpdir-.}" "$prefix.XXXXXX")"

declare tmp_sam="$(mktemp -p "$tmpdir" "$prefix.sam.tmp.XXXXXX")" \
        tmp_split_prefix="$(mktemp -p "$tmpdir" "$prefix.split.tmp.XXXXXX")" \
        out_supp_sam="$outdir/$prefix.second_supp.sam${suffix}" \
        out_metrics="$outdir/$prefix.picard_markdup.metrics.txt${suffix}"

if [[ "$markdup" == "true"] ] ; then
    declare outfile="$outdir/$prefix.bam${suffix}"
else
    declare outfile="$outdir/$prefix.sam${suffix}"

minimap2_kws+=(--split-prefix "$tmp_split_prefix")

if [[ $verbose == true ]] ; then

    cat <<-ARGS
	Script: $(basename "$0")  ($0)

	Arguments
	---------
	Reference fasta:   $ref_fasta
	Forward reads:     $reads1
	Reverse reads:     $reads2
	Output directory:  $outdir
    Temp directory:    $tmpdir

	Remove duplicates: $rmdup
	Mark duplicates:   $markdup
	Number of threads: $threads
	Read group:        ${read_group:-}
	
	Programs
	--------
	fqtools  : $(fqtools -v 2>&1) ($(which fqtools))
	minimap2 : $(minimap2 --version 2>&1) ($(which minimap2))
	samtools : $(samtools --version 2>&1 | head -n 1) ($(which samtools))
	Picard   : $(java -jar "$PICARD_JAR" MarkDuplicates --version 2>&1) ($PICARD_JAR)
	
	Output
	------
	> Output SAM : $outfile
	> Secondary alignments & supplementary lines : $out_supp_sam
	$( [[ $markdup == "true" ]] && echo '> MarkDuplicates metrics :' "$out_metrics" )
	ARGS
fi

declare read_count=$(fqtools count "$reads1" "$reads2")

declare expected_read_count=$(( 2 * read_count ))

echo "Expected read count: $expected_read_count"

# run minimap2 with args and pipe to awk to split into two files. 
# (secondary and supplementary alignments put into in a separate file)
# headers are written to in both
declare v_set="${-//[^v]/}"
minimap2 \
    "${minimap2_kws[@]}"  \
    "$ref_fasta" "$reads1" "$reads2" \
    | awk -F "\t" -v OFS="\t" '''
        and($2, 256) || and($2, 2048) { print $0>"/dev/fd/3"; next ; }
        /^@/  { print $0>"/dev/fd/1" ; print $0>"/dev/fd/3" ; next ; }
        { print $0>"/dev/fd/1" ; }
    ''' 1>"$tmp_sam" 3>"$out_supp_sam"

# get number of reads in output sam
declare number_in_sam=$(grep -cvE "^@" "$tmp_sam")

echo "Number in sam: $number_in_sam"

if (( expected_read_count != number_in_sam )) ; then
    echo "Error: mismatched read counts. Expected $expected_read_count but got $number_in_sam" \
        >&2 && exit 1
fi

# post-map processing
if [[ "$rmdup" == "true" ]] ; then
    # remove duplicates
    echo "Removing duplicates..." 
    samtools sort -O BAM -@ $(( threads - 1 )) | samtools rmdup - "$outfile" 

elif [[ "$markdup" == "true" ]] ; then
    echo "Marking duplicates..." 
    # make sorted bam first (for picard input)
    declare tmp_sorted_bam="$(mktemp -p "$outdir" "$prefix.srt.bam.tmp.XXXXXX")"
    samtools sort -O BAM -@ $(( threads - 1 )) > "$tmp_sorted_bam" && \
        java -Xmx2G -jar "$PICARD_JAR" \
            MarkDuplicates "${markdup_kws[@]}" \
            INPUT="$tmp_sorted_bam" OUTPUT="$outfile" M="$out_metrics"

else
    # no further action needed
    mv "$tmp_sam" "$outfile"
fi
