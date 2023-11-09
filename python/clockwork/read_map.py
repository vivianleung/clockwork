import tempfile
import shutil
import os
import pysam
from clockwork import fqtools, picard, utils


def map_reads(
    ref_fasta: str,
    reads1: str,
    reads2: str,
    outfile: str,
    rmdup: bool = False,
    markdup: bool = False,
    read_group: tuple[int, str] = None,
    threads: int = 1,
    minimap2_preset: str = "sr",
):
    """Maps reads with minimap2. By default, outputs SAM file in input read order.
    rmdup=True => remove duplicates using samtools rmdup. Final output is sorted bam
                  Incompatible with markdup=True
    markdup=True => mark duplicates using picard MarkDuplicate. Final output is sorted bam.
                  Incompatible with rmdup=True
    read_group should be a tuple (group_id, group_name). If given, these will be
    put into the BAM"""
    if rmdup and markdup:
        raise Exception("Cannot have rmdup and markdup both True.")

    try:
        expected_read_count = 2 * fqtools.count([reads1, reads2])
    except:
        raise Exception("Error counting reads in input files " + reads1 + " " + reads2)

    if rmdup or markdup:
        tmpdir = tempfile.mkdtemp(
            prefix=outfile + ".tmp.map_reads.", dir=os.path.dirname(outfile)
        )
        sam_file = os.path.join(tmpdir, "tmp.sam")
    else:
        sam_file = outfile

    # "LB:LIB" is needed, otherwise samtools rmdup segfaults when map_reads_set() is used
    R_option = (
        ""
        if read_group is None
        else r"""-R '@RG\tLB:LIB\tID:"""
        + read_group[0]
        + r"""\tSM:"""
        + read_group[1]
        + "'"
    )

    # If we're using a reference in a directory made by clockwork reference_prepare,
    # then there will a minimap2 index file already there we can use.
    minimap2_index = ref_fasta + ".minimap2_idx"
    ref_file = minimap2_index if os.path.exists(minimap2_index) else ref_fasta

    cmd = " ".join(
        [
            "minimap2",
            f"--split-prefix {sam_file}.tmp",
            "-a",
            f"-t {threads}",
            f"-x {minimap2_preset}",
            R_option,
            ref_file,
            reads1,
            reads2,
            r""" | awk '/^@/ || !(and($2,256) || and($2,2048))' """,  # remove secondary and supplementary alignments (but keep header)
            
            ">",
            sam_file,
        ]
    )

    try:
        utils.syscall(cmd)
    except Exception as error:
        if rmdup or markdup:
            shutil.rmtree(tmpdir)
        raise Exception("Error running BWA MEM: " + cmd) from error

    number_in_sam = utils.sam_record_count(sam_file)
    if expected_read_count != number_in_sam:
        if rmdup or markdup:
            shutil.rmtree(tmpdir)
        raise Exception(
            "Error! Mismatch in read counts. Expected "
            + str(expected_read_count)
            + " but got "
            + str(number_in_sam)
        )

    if rmdup or markdup:
        sorted_bam = os.path.join(tmpdir, "tmp.sorted.bam")

        cmd = " ".join(["samtools sort", "-o", sorted_bam, sam_file])

        try:
            utils.syscall(cmd)
        except Exception as error:
            shutil.rmtree(tmpdir)
            raise Exception("Error running samtools sort: " + cmd) from error

        if rmdup:
            cmd = "samtools rmdup " + sorted_bam + " " + outfile
            try:
                utils.syscall(cmd)
            except Exception as error:
                shutil.rmtree(tmpdir)
                raise Exception("Error running samtools rmdup: " + cmd) from error
        else:
            try:
                picard.mark_duplicates(sorted_bam, outfile)
            except Exception as error:
                shutil.rmtree(tmpdir)
                raise Exception("Error running picard mark_duplicates " + cmd) from error

        shutil.rmtree(tmpdir)


def map_reads_set(
    ref_fasta,
    reads1_list,
    reads2_list,
    outfile,
    rmdup=False,
    markdup=False,
    read_group=None,
    threads=1,
):
    """Same as map reads, but takes a list of file pairs to be mapped"""
    assert len(reads1_list) == len(reads2_list)
    outfile = os.path.abspath(outfile)
    tmpdir = tempfile.mkdtemp(
        prefix=outfile + ".tmp.map_reads_set.", dir=os.path.dirname(outfile)
    )
    outfiles = []

    for i, (reads1, reads2) in enumerate(zip(reads1_list, reads2_list)):
        
        
        outfiles.append(os.path.join(tmpdir, "map." + str(i)))
        map_reads(
            ref_fasta,
            reads1,
            reads2,
            outfiles[-1],
            rmdup=rmdup,
            markdup=markdup,
            read_group=read_group,
            threads=threads,
        )

    assert len(outfiles) == len(reads1_list)

    if len(outfiles) == 1:
        os.rename(outfiles[-1], outfile)
    else:
        flags = ["-c"]
        if not (rmdup or markdup):
            flags.append("-n")
        pysam.merge(*flags, outfile, *outfiles)

    shutil.rmtree(tmpdir)
