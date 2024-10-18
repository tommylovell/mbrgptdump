#define  _LARGEFILE_SOURCE
#define  _LARGEFILE64_SOURCE
#define __USE_LARGEFILE64
#define __USE_FILE_OFFSET64
#define  VERS        "1.05"

/*  -------------  */
/*  default flags  */
/*  -------------  */
#define  DEBUG_FLAG  1 /* '1' prints debug info, i.e., a hexdump of many areas; '0' does not */
#define  OUTPUT_FLAG 0 /* '1' produces output files, .mn, .gn, .hn suffixed; '0' doesn't */

#define  NUMBUFS     128    /*  read-ahead normally this, or larger  */
#define  PARTITIONS  65536  /* number of partitions to process      */
#define  S           512 /* logical sector size; physical sector size seems to be irrelevant */
#define  GPT_BLOCK_SIZE 512    /* for now */
#define  GPT_HEADER_REVISION_V1 0x00010000

int      debug=DEBUG_FLAG;  /*  'debug' is a global value, it's here so    */
                            /*  we don't have to pass it to each function  */
int      output=OUTPUT_FLAG;  /*  same with output'  */
int      nooutput=0;
/*
    This is a C program that lists the contents of the partition table(s) of either a specific
    disk or disk '.img', and (optionally, -o flag) writes each partition as a separate file.

    This is what the makefile can look like for the following C code. It goes in
    the same directory as the C source. The makefile copies the executable to '~/bin'
    (which is in the Raspberry Pi $PATH), so it is easier to execute. Conversely, you
    can move the executable into '/usr/local/bin' by replacing the 'mv' command with:
        sudo mv ${PROGS} /usr/local/bin/${PROGS}
    (remember it's a makefile, so tab out to 'sudo'):

    You also won't have to 'sudo' it if it's 'chown'd/'chmod'd.

    The "disk" that the executable runs against, can either be a device (e.g.
    /dev/mmcblk0) or an unzipped file (e.g. 2022-09-22-raspios-bullseye-armhf.img).

TEMPFILES = *.o *.out
PROGS = split_it

all:
	gcc -o ${PROGS} ${PROGS}.c
	sudo chown root:root ${PROGS}
	sudo chmod u+s       ${PROGS}
	mkdir ~/bin
	sudo mv ${PROGS} ~/bin/${PROGS}

clean:
	-rm -f ${PROGS} ${TEMPFILES}
	sudo rm ~/bin/${PROGS}
	sudo rm /usr/local/bin/${PROGS}


    By doing the chown/chmod, You won't have to 'sudo'. I know, huge security hole.
    There is a check done to make sure you are EUID == root, in case the source is
    inaccessible by your uid.

    The "disk" that the executable runs against, can either be a device (e.g.
    /dev/mmcblk0) or an unzipped file (e.g. 2022-09-22-raspios-bullseye-armhf.img).
*/

/*
MIT License

Copyright (c) 2023 Thomas Lovell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
/* Whew.  Do I really need that? Anyone can use it; anyway they want too; */
/* I didn't invent anything; others may have copywrite rights; don't sue me. */
/*
   This code is only executed a few times (and it's promarily for self-education),
   so,
   it doesn't have to be efficient;
   it doesn't have to be elegant (and god knows, it's not);
   it just needs to work!  And it mostly does...
   But it probably has bugs and logic errors (leave comments);
   and take what it says with a "grain of salt".

   It's just a cheap little utility cobbled together from other C programs to show
   me what is on "disk", and then optonally creates "partition files" (m1, m2 mn,
   h1, h2, hn, g1, g2, gn, etc.).

   There is a lot of variability on what is on a GPT disk (e.g. is there a pMBR -
   protective MBR entry? Sometimes. Do the primary MBR partition(s) have coresponding
   GPT partition(s) (a "hybrid drive)? They might, but who knows...
   and does a pMBR preceed or follow those DOS/MBR primary partitions?...)
*/

#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <getopt.h>    /* for getopt_long */
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <uchar.h>
#include <time.h>

typedef struct mbr_ent_tag {
    unsigned char status[1];
    unsigned char starting_CHS[3]; /* no longer used */
    unsigned char type;
    unsigned char ending_CHS[3];   /* no longer used */
    unsigned int  starting_lba;
    unsigned int  num_sectors;     /* limits dos mbr disk to 0xffffffff */
} __attribute__((aligned(4))) mbr_ent;  /* make sure struct is int aligned... */

typedef char16_t efi_char16_t;  /* somehow this was never defined as a type... ??? */

typedef struct mbr_pN_tag {
    unsigned char status[1];
    unsigned char chs_first[3];
    unsigned char type[1];
    unsigned char chs_last[3];
    unsigned char lba[4];
    unsigned char num[4];
} pN_ent;

char zeros[S]; /* ... a "global" constant; no use defining it in mult. functions  */

void hexDump(char *desc, void *addr, int len);
void guid_raw_to_string(char* raw, char* str);
int  write_MBR_partition(mbr_ent *mbr_tbl, uint64_t i, char *ifn, char *ofn);
int  write_GPT_partition(mbr_ent *mbr_tbl, uint64_t i, char *ifn, char *ofn,
             int mbr_flag, uint64_t start, uint64_t num);


/*  +-----------------------------------------------------------+  */
/*  |  +------------------------------------------------------+ |  */
/*  |  |  finally.  here's the start of the main() function.  | |  */
/*  |  |  thank god for cut-and-paste.                        | |  */
/*  |  +------------------------------------------------------+ |  */
/*  +-----------------------------------------------------------+  */
int main(int argc, char **argv) {
    int      ifd, ifdalt, ofd;
    char     ifn[S]="/dev/sda", ofn[S+3]="";
    int      ret, x;
    ssize_t  sz=0;
    int      errsv;
    off64_t  off64t, ofalt, start;
    uint64_t of, num, num_sec;
    unsigned short int sig=43605; /* this is 0x55aa */
    char     sig2[]="EFI PART";
    int      mbr_flag=1;   /* Assume for now that we have a MBR */
    int      alternate=1;
    char     string_disk_guid[]="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee  ";
    uint64_t i, j;
    int      c, digit_optind = 0, HELP=0, numbufs=NUMBUFS, partitions=PARTITIONS;
    char     OUTPUT[128];
    pN_ent   *pN_tbl_ptr;

    typedef char16_t efi_char16_t;  /* somehow this was never defined as a type... ??? */

    typedef struct mbr_pN_ent_tag {
        unsigned char status[1];
        unsigned char chs_first[3];
        unsigned char type[1];
        unsigned char chs_last[3];
        unsigned char lba[4];
        unsigned char num[4];
    } pN_ent;

    typedef union gpt_entry_attributes_tag {
        struct {
            uint64_t required_to_function:1;
            uint64_t no_block_io_protocol:1;
            uint64_t legacy_bios_bootable:1;
            uint64_t reserved:45;
            uint64_t type_guid_specific:16;
        } fields;
        unsigned long long raw;
    } gpt_entry_attributes;

    union rec_tag {
        char    buf[S];
        struct mbr_tag {
            char reserved1[440];
            unsigned char diskid[4];
            char diskid2[2];
            pN_ent p1;
            pN_ent p2;
            pN_ent p3;
            pN_ent p4;
            unsigned char disksig[2];
        } mbr;
        struct gpt_header_tag {
            uint64_t signature;
            uint32_t revision;
            uint32_t header_size;
            uint32_t header_crc32;
            uint32_t reserved1;
            uint64_t my_lba;
            uint64_t alternate_lba;
            uint64_t first_usable_lba;
            uint64_t last_usable_lba;
            char     disk_guid[16];
            uint64_t partition_entry_lba;
            uint32_t num_partition_entries;
            uint32_t sizeof_partition_entry;
            uint32_t partition_entry_array_crc32;
            uint8_t  reserved2[GPT_BLOCK_SIZE - 92];
        } gpt_header;
        struct gpt_entry_tag {
            char     partition_type_guid[16];
            char     unique_partition_guid[16];
            uint64_t starting_lba;
            uint64_t ending_lba;
            gpt_entry_attributes attributes;
            efi_char16_t partition_name[72 / sizeof(efi_char16_t)];
        } gpt_entry;
    } rec;

    char    brec[sizeof(rec.gpt_header)];

    mbr_ent  mbr_tbl[4];  /*  4-entry table containing MBR partition info  */
    pN_tbl_ptr = (struct mbr_pN_tag *) &rec.mbr.p1;
                          /*  4-entry table of ptrs to MBR part info on disk */

/*  stuff saved from the GPT header  */
     long unsigned int gpth_revision=0;
     long unsigned int gpth_header_size=0;
long long unsigned int gpth_my_lba=0;
long long unsigned int gpth_alternate_lba=0;
long long unsigned int gpth_first_usable_lba=0;
long long unsigned int gpth_last_usable_lba=0;
long long unsigned int gpth_partition_entry_lba=0;
                  char gpth_disk_guid[16];
     long unsigned int gpth_num_partition_entries=0;
     long unsigned int gpth_sizeof_partition_entry=0;

    if (geteuid() != 0) {
        fprintf(stderr, "EUID not 0; you  may have to run as root, or sudo, to access a disk device or .img file\n");
    }

    /*  --------------------------------------------  */
    /*  process any arguments passed to this program  */
    /*  --------------------------------------------  */
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"debug",      no_argument,       0, 'd'},
            {"help",       no_argument,       0, 'h'},
            {"version",    no_argument,       0, 'v'},
            {"output",     no_argument,       0, 'o'},
            {"nooutput",   no_argument,       0, 'n'},
            {"partitions", required_argument, 0, 'p'},
            {0,            0,                 0,  0}
        };  /* end of 'struct'  */

        c = getopt_long(argc, argv, "dhvonp:", long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'd':
                debug=1;  /*  just set the debug flag  */
                break;

            case 'h':
                printf("  %s [-d] [-o] [-n] [-pN] [-h] [-v] [<blkdev>or<fn.img>]\n\n", argv[0]);
                printf("  This program lists the partitions of a specific disk or disk image\n");
                printf("  (e.g. '/dev/mmcblk0', '2023-02-21-raspios-bullseye-armhf.img' or\n");
                printf("  'starfive-jh7110-VF2-SD-wayland.img').  It also (optionally) writes each\n");
                printf("  partition's data as a separate file, which is then mountable (on loopback).\n\n");
                printf("  It accepts the following flags ('[' and ']' denote optional):\n");
                printf("    --debug or -d\n");
                printf("        produce debug output (mostly as a learning aid)\n");
                printf("    --output or -o\n");
                printf("        output each partition's data as a mountable filesystem (on loopback) adding\n");
                printf("        '.gN' (GPT), '-hN' (hybrid), or '.mN' (MBR) (where 'N' is the partition\n");
                printf("        number) to a base filename. The base filename is the input filename unless\n");
                printf("        a block device is specified as input (i.e. /dev/<something>).\n");
                printf("        In that case, the slashes are converted to underscores.\n");
                printf("        If '-o' is omitted, then just a list of partitiions is produced.\n\n");
                printf("        Also, if you want to save disk space, use 'fallocate -d <filename>' to\n");
                printf("        make each output a sparse file. (This program used to have this as an\n");
                printf("        option, but it is better to use something that already exists and is\n");
                printf("        more universal.) (Plus, not every filesystem supports 'sparse', or will\n");
                printf("        continue to support 'sparse'.)\n\n");
                printf("        A special case: if the '-n' flag is specified, it overrides this flag.\n");
                printf("    --nooutput or -n\n");
                printf("        does not produce output file(s). It still reads the input partition data\n");
                printf("        but discards the output.\n");
                printf("    --partitions=n or -p n\n");
                printf("        highest partition number to output (default is all). '-o' must be specified.\n");
                printf("    --help or -h\n");
                printf("        this text, then exits. all other flags ignored.\n");
                printf("    --version or -v\n");
                printf("        outputs version number, then exits. all other flags ignored.\n\n");
                printf("  Flags must be all lower case. The last flag usually \"wins\".\n\n");
                printf("  Example invocations:\n");
                printf("      %s -d\n", argv[0]);
                printf("      %s -o\n", argv[0]);
                printf("      %s -d -o -p4\n", argv[0]);
                printf("      %s -o  disk.img\n", argv[0]);
                exit(0);

            case 'v':
                printf("'%s' version %s\n", argv[0], VERS);
                exit(0);

            case 'o':
                output = 1;
                break;

            case 'n':
                output = 1;
                nooutput = 1;
                strcpy(ofn, "/dev/null");
                break;

            case 'p':
                if (optarg != 0) {
                    if ((partitions = atoi(optarg)) == 0) {
                        fprintf(stderr, "-p/--partition value, %s, invalid; exiting\n",
                            optarg);
                        exit(1);
                    }
                    break;
                } else {
                    fprintf(stderr, "-p/--partition value missing; exiting\n");
                    exit(1);
                }
                break;

            case '?':
                break;

            default:
                printf("?? getopt returned character code %c ??\n", c);

        }  /*  end of 'switch'  */
    }  /*  end of 'while'  */

    if (optind < argc) {  /*  if any non-arguments were specified, the first is the input fn  */
        strncpy(ifn, argv[optind++], sizeof(ifn));
        printf("input file name specified; set to %s\n", ifn);
        while (optind < argc) printf("these excess arguments will be ignored, %s\n", argv[optind++]);
    }  /* end of 'if (optind'  */

    if ((strcmp(ofn, ""))             == 0) strcpy(ofn, ifn);         /*  if no fn, set to input name  */

    if (strcmp(ofn, "/dev/null")) for(x=0; x<sizeof(ofn)+1; x++) if(ofn[x] == '/') ofn[x] = '_';
    /*  if the output filename is not /dev/null, just translate '/' to '_'. Cheap code-only done once  */

    printf("output file base name set to %s\n", ofn);
    if (! output) printf("  but '-o' flag not specified, so partition data will not be outputted\n");
    printf("\n");

    memset(zeros, '\0', sizeof(zeros));  /*  zero out variable 'zeros'  */

    /*  ---------------------------------  */
    /*  open input to read partition info  */
    /*  ---------------------------------  */
    if ((ifd = open(ifn, O_RDONLY | O_LARGEFILE)) == -1) {  /*  open input  */
        errsv = errno;
        fprintf(stderr, "The input file '%s' could not be opened\n", ifn);
        fprintf(stderr, " errno is '%i - %s'\n", errsv, strerror(errsv));
        exit(4);
    }

    if ((ifdalt = open(ifn, O_RDONLY | O_LARGEFILE)) == -1) {
        /* an error shouldn't happen, but we check anyway */
        errsv = errno;
        fprintf(stderr, "'open' failed for alt, '%s', ???\n", ifn);
        fprintf(stderr, " errno is '%i - %s'\n", errsv, strerror(errsv));
        exit(4);
    }

    /*  ---------------------------  */
    /*  read 1st sector; lba=0; MBR  */
    /*  ---------------------------  */
    if ((sz = read(ifd, (void *) rec.buf, S)) == S) {
        /* does sector have 0x55aa signiture at end?  */
        if (memcmp(&rec.mbr.disksig, &sig, 2) != 0) {
            printf("Input file disk signature, %x%x, not 0x55aa.\n",
                    rec.mbr.disksig[0], rec.mbr.disksig[1]);
            printf("Assuming no MBR present!");
            mbr_flag=0;
        }
    } else {
        fprintf(stderr, "size read, %u, not %i; exiting\n", (unsigned int) sz, S);
        exit(4);
    }

    if (mbr_flag) {
        /*  -----------------------------------------------------  */
        /*  save the MBR partition in a small table and print info */
        /*  -----------------------------------------------------  */
        printf("MBR diskID: 0x%02x%02x%02x%02x\n",
            (unsigned char) rec.mbr.diskid[3], (unsigned char) rec.mbr.diskid[2],
            (unsigned char) rec.mbr.diskid[1], (unsigned char) rec.mbr.diskid[0]);
        /*  -----------------------------------------------------  */
        /*  save the MBR partition in a small table and print info */
        /*  -----------------------------------------------------  */
        /*  there is no guaranteed alignment of 'lba' and 'num',   */
        /*  so we can't do simple assignments, we have to do       */
        /*  'moves' to variables that are properly aligned.        */
        /*  -----------------------------------------------------  */
        for (i=0; i < 4; i++) {
            memcpy(&(mbr_tbl+i)->status,        &(pN_tbl_ptr+i)->status, 16);
	    if ((mbr_tbl+i)->type == 0) continue; /* nothing to see here.  move along */
            printf("MBR partition %llu: starting sector:%12u; ending sector:%12u; number of sectors:%12u; type: %02x\n",
                (long long unsigned int) i+1,
                (mbr_tbl+i)->starting_lba,
               ((mbr_tbl+i)->num_sectors + (mbr_tbl+i)->starting_lba -1),
                (mbr_tbl+i)->num_sectors,
                (mbr_tbl+i)->type);
        }  /*  end of 'for (i=0; i<4; i++)' */
        printf("\n");

        if (debug) hexDump("Saved MBR data", mbr_tbl, 4*sizeof(mbr_ent));
     }

    /*  --------------------------  */
    /*  read second sector; lba 1;  */
    /*  --------------------------  */
    of = S;
    off64t = lseek64(ifd, of, SEEK_SET);
    if ((sz = read(ifd, (void *) rec.buf, (int) S)) == (int) S) {
        if (!  memcmp(&rec.gpt_header.signature, &sig2, 8) == 0) {
            printf("There is no GPT header\n");
            if (mbr_flag) {
                printf("This is a legacy MBR disk (/dev/<block device>) or disk-image (e.g. RPi .img file)\n");

                if (output) {
                    printf("Output files (if requested with the '-o' flag) will be suffixed ");
                    printf("with '.m' and the MBR primary partition number.\n");

                    ( partitions > 3 ) ? (j=3) : (j=--partitions) ;

                    printf("Up to %llu partitions will be dumped\n", (long long unsigned int) j+1);

                    for (i=0; i <= j; i++) {
                        if ((ret = write_MBR_partition((mbr_tbl), i, ifn, ofn)) == 0) {
                            printf("\nMBR partition %i copied to file successfully!\n", (int) i+1);
                        } else if (ret == -1) {
                            printf("\nMBR partition %i read but written to '/dev/null'\n", (int) i+1);
                        } else {
                            printf("failed to write partition %i; exiting\n", (int) i+1);
                            exit(1);
                        }  /*  end of 'if ((ret = write_MBR_partition'  */
                    }  /*  end of 'for (i=0;'  */
                } else {
                    printf("\nflag set to NOT produce partition data output!!!\n\n");
                }  /*  end of 'if (output)  */
            } else {
                printf("There is no MBR partition table, either\n");
            }  /*  end of 'if (MBR)'

            if (debug) {
                if ((memcmp(&rec.gpt_header, &zeros, S)) == 0) {
                    printf("GPT header all zeros\n");
                } else {
                    hexDump("GPT header", &rec.buf, S);
                }
            }  /*  end of 'if (debug)  */

            exit(0);
        }  /*  end of 'if (! memcmp'  */

        /*  ----------------------------------------------  */
        /*  There is a valid GPT header; save info from it  */
        /*  ----------------------------------------------  */
        gpth_revision                        = rec.gpt_header.revision;
        gpth_header_size                     = rec.gpt_header.header_size;
        gpth_my_lba                          = rec.gpt_header.my_lba;
        gpth_alternate_lba                   = rec.gpt_header.alternate_lba;
        gpth_first_usable_lba                = rec.gpt_header.first_usable_lba;
        gpth_last_usable_lba                 = rec.gpt_header.last_usable_lba;
        memcpy (&gpth_disk_guid,              &rec.gpt_header.disk_guid,             16);
        gpth_partition_entry_lba             = rec.gpt_header.partition_entry_lba;
        gpth_num_partition_entries           = rec.gpt_header.num_partition_entries;
        gpth_sizeof_partition_entry          = rec.gpt_header.sizeof_partition_entry;

        printf("GPT Header Signature, 'EFI PART', is present\n");
        printf("GPT Header Revision is ");
        if (gpth_revision == GPT_HEADER_REVISION_V1) {
            printf("1.0\n");
        } else {
        printf("not known; exiting\n");
        exit(4);
        }  /*  end of 'if (gpth_revision'  */
    }  /*  end of 'if ((sz = read'  */

    /*  ------------------------------------  */
    /*  print out all of the GPT header info  */
    /*  ------------------------------------  */
    printf("GPT Header Size is %li\n", gpth_header_size);
    /* (the uint64_t info was copied to lli variables so that this code
     * could run on both 32-bit and 64-bit systems without a big hassle.) */
    printf("GPT Header LBA  is %lli\n", gpth_my_lba);
    printf("Backup GPT Header LBA is at %lli\n", gpth_alternate_lba);
    printf("First usable LBA for partitions is %lli\n", gpth_first_usable_lba);
    printf("Last  usable LBA for partitions is %lli\n", gpth_last_usable_lba);
    /* (this is very strange! Wikipedia calls this 'mixed endian'. */
    /* I call it "designed by a committee...")                     */
    guid_raw_to_string(gpth_disk_guid, string_disk_guid);
    printf("Disk GUID is %s\n", string_disk_guid);
    printf("Starting LBA of partition entries is %lli\n", gpth_partition_entry_lba);
    printf("Number of partition entries is %li\n", gpth_num_partition_entries);
    printf("Size of each partition entry is %li\n", gpth_sizeof_partition_entry);

    if (debug)  hexDump("Primary GPT header", &rec.gpt_header.signature, 92);

    /*  -----------------------------------------------------------  */
    /*  read alternate GPT header and compare to primary GPT header  */
    /*  -----------------------------------------------------------  */
    ofalt = gpth_alternate_lba*S;    /* calc offset to backup GPT header */
    off64t = lseek64(ifdalt, ofalt, SEEK_SET);    /*  <---- needs error checking ----<  */
    if ((sz = read(ifdalt, (void *) brec, S)) == S) {    /* read backup GPT header */
        if (memcmp(&rec.gpt_header, &brec, S)) {    /* primary v alternate */
            printf("GPT header and alternate GPT headers agree\n");
            alternate=1;
        } else {
            printf("GPT header and alternate GPT headers don't agree\n");
            alternate=0;
	    /*  hexDump entire sector, 'cuz GOK what it is  */
            if (debug) hexDump("Alternate GPT header", &brec, 512);
        }  /*  end of 'if (memcmp'  */
    }  /*  end of 'if ((sz ='  */

    /*  ----------------------------------  */
    /*  loop through GPT partition entries  */
    /*  ----------------------------------  */

    /*  ----------------------------------  */
    /*  print out GPT partition info first  */
    /*  ----------------------------------  */
    /* position ifd at the beginning of the primary partition entries */
    of = gpth_partition_entry_lba*S;
    off64t = lseek64(ifd, of, SEEK_SET);
    /* position ifdalt at the beginning of the alternate partition entries */
    ofalt= gpth_alternate_lba*S-(gpth_num_partition_entries*gpth_sizeof_partition_entry);
    off64t = lseek64(ifdalt, ofalt, SEEK_SET);
    /*  --------------------------------------------------  */
    /*  do all the GPT entries; it'll just take a microsec  */
    /*  --------------------------------------------------  */
    printf("\n");
    for (i=1; i < gpth_num_partition_entries+1; i++) {
        /*  ---------------------------------------  */
        /*  read the Primary GPT entry and print it  */
        /*  (we'll check the alternate GPT later)    */
        /*  todo: move alternate checking here...    */
        /*  ---------------------------------------  */
        if ((sz = read(ifd, (void *) rec.buf, gpth_sizeof_partition_entry)) ==
                        gpth_sizeof_partition_entry) {    /* read GPT entry */
            if ((num_sec = rec.gpt_entry.ending_lba - rec.gpt_entry.starting_lba) == 0) continue;
            printf("GPT partition %4lu: starting sector:%12llu; ending sector:%12llu; number of sectors:%12lu; type: %02x\n",
                             (long int) i,
                        (long long int) rec.gpt_entry.starting_lba,
                        (long long int) rec.gpt_entry.ending_lba,
                        ++num_sec,
                        0);
            if (debug) hexDump("GPT partition entry", rec.buf, 92);
        } else {
            fprintf(stderr, "partition, %ui, size read, %i, not %i; exiting\n", (int) i, (int) sz, (int) gpth_sizeof_partition_entry);
            exit(4);
        }  /*  end of 'if ((sz = read(ifd'  */
    }  /*  end of 'for (i=1;'  */

    /*  ----------------------------------------  */
    /*  now write out partition data if flag set  */
    /*  ----------------------------------------  */

    if (output != 0) {  /*  more work to do  */

        /* position ifd at the beginning of the primary partition entries */
        of = gpth_partition_entry_lba*S;
        off64t = lseek64(ifd, of, SEEK_SET);

        /* position ifdalt at the beginning of the alternate partition entries */
        ofalt= gpth_alternate_lba*S-(gpth_num_partition_entries*gpth_sizeof_partition_entry);
        off64t = lseek64(ifdalt, ofalt, SEEK_SET);

        /*  ------------------------  */
        /*  dump all the GPT entries  */
        /*  ------------------------  */
        ( partitions > gpth_num_partition_entries ) ? (j=gpth_num_partition_entries) : (j=partitions) ;

        if (debug) printf("%zd partitions will be dumped\n", j);

        for (i=1; i < j+1; i++) {
            /*  --------------------------  */
            /*  read the Primary GPT entry  */
            /*  --------------------------  */
            if ((sz = read(ifd, (void *) rec.buf, gpth_sizeof_partition_entry)) ==
                        gpth_sizeof_partition_entry) {    /* read GPT entry */
                if ((rec.gpt_entry.ending_lba - rec.gpt_entry.starting_lba) == 0) continue;
                printf("\nGPT partition %i\n", (int) i);
                guid_raw_to_string((char *) rec.gpt_entry.partition_type_guid, string_disk_guid);
                printf("GPT partition entry partition type GUID is %s\n", string_disk_guid);
                guid_raw_to_string((char *) rec.gpt_entry.unique_partition_guid, string_disk_guid);
                printf("GPT partition entry unique partition GUID is %s\n", string_disk_guid);
                printf("GPT partition entry starting LBA is %lli\n",
                         (long long int) rec.gpt_entry.starting_lba);
                printf("GPT partition entry ending   LBA is %lli\n",
                         (long long int) rec.gpt_entry.ending_lba);
                if (debug) hexDump("GPT entry", &rec.buf, gpth_sizeof_partition_entry);
            } else {
                fprintf(stderr, "partition, %i, size read, %i, not %i; exiting\n", (int) i, (int) sz, (int) gpth_sizeof_partition_entry);
                exit(4);
            }  /*  end of 'if ((sz = read'  */

            /*  ----------------------------  */
            /*  read the Alternate GPT entry  */
            /*  todo: move this alternate GPT entry checking code to up above...  */
            /*  ----------------------------  */
            if ((sz = read(ifdalt, (void *) brec, gpth_sizeof_partition_entry)) ==
                        (size_t) gpth_sizeof_partition_entry) {

                /*  -------------------------------------------------  */
                /*  are the primary GPT entry and alternate the same?  */
                /*  -------------------------------------------------  */
                if ((memcmp(&rec.buf, &brec, gpth_sizeof_partition_entry)) == 0) {
                    printf("primary GPT partition entry and alternate agree\n");
                } else {
                    printf("primary GPT partition entry and alternate disagree\n");
                    hexDump("GPT alternate partition entry", &brec, gpth_sizeof_partition_entry);
                }  /* end of 'if ((memcmp'  */

                /*  ------------------------------------------------  */
                /*  calculate how many sectors are in this partition  */
                /*  ------------------------------------------------  */
                num = rec.gpt_entry.ending_lba - rec.gpt_entry.starting_lba + 1;

                /*  -------------------------------------------------------  */
                /*  if this partition does not exist, continue the for loop  */
                /*  -------------------------------------------------------  */
                if ((num_sec = rec.gpt_entry.ending_lba - rec.gpt_entry.starting_lba) == 0) continue;

                /*  -----------------------------------------------  */
                /*  else, try to write the partition data to a file  */
                /*  -----------------------------------------------  */
                if ((ret = write_GPT_partition(mbr_tbl, i, ifn, ofn, mbr_flag,
                        rec.gpt_entry.starting_lba, num)) == 0) {
                    printf("\nGPT partition %i copied to file successfully!\n", (int) i);
                } else if (ret == -1) {
                    printf("\nGPT partition %i read but written to '/dev/null'\n", (int) i);
                } else {
                    printf("\nfailed to write GPT partition, %i; exiting\n", (int) i);
                    exit(4);
                }  /*  end of 'if ((write_GPT_partition'  */
            } else {
                fprintf(stderr, "size read, %li, not %li; exiting\n", sz, gpth_sizeof_partition_entry);
                exit(4);
            }  /*  end of 'if ((sz = read'  */
        } /*  we're done with this drive/image  */
       close(ifd);
       exit(0);
    } else {
       printf("\nflag set to NOT produce partition data output!!!\n\n");
    }  /* end of 'if (output)'  */
}  /* end of 'main()'  */
/*  --------------------------------------------  */
/*  'main' function done; other functions follow  */
/*  --------------------------------------------  */


/* -------------------------------------------------------------------------------- */
/* 'guid_raw_to_string' is a function that converts a "mixed endian" GUID           */
/* (that is, a 4 byte little endian; a 2 byte LE; a 2 byte LE; a 2 byte Big Endian; */
/* and finally a 6 byte BE - 16 bytes in total)                                     */
/* to an ascii string in the formal aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee            */
/* -------------------------------------------------------------------------------- */
void guid_raw_to_string(char* guid, char* st) {
    unsigned char *r = (unsigned char*)guid;
    sprintf(st,"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        r[3],r[2],r[1],r[0],r[5],r[4],r[7],r[6],r[8],r[9],r[10],r[11],r[12],r[13],
	r[14],r[15]);
}

/* -------------------------------------------------------------------------------- */
/*   ----------------------------------------------------------------------------   */
/*   write out each of the MBR primary partitions to a separate file                */
/*   we will open the input and reposition it again as a 2nd fd so we don't upset   */
/*   the partition reading code                                                     */
/*   ps. don't write out the protective MBR, as it is not a real partition          */
/*   ----------------------------------------------------------------------------   */
/*   we're passed: the 4-entry MBR table: which of the 4 partitions to write;       */
/*   the input file name; and the output file name                                  */
/*   ----------------------------------------------------------------------------   */
/* -------------------------------------------------------------------------------- */
int write_MBR_partition(mbr_ent *mbr_tbl, uint64_t i, char *ifn, char *ofn) {
    int64_t off64t, sectors, progress, mod=100000;
    int     ifd, ofd, errsv;
    uint64_t of = 0;
    char    sprintf_buf[12], fn[S+3], buf[S], pMBR=0xee;
    ssize_t bytes_read, bytes_written;

    if ((mbr_tbl+i)->num_sectors == 0) return 1;                      /* ignore unused entry  */
    if ((mbr_tbl+i)->starting_lba == 0) return 1;                     /* ignore unused entry  */
    if (memcmp(&(mbr_tbl)->type, &pMBR, 1)  == 0) return 1;         /* ignore pMBR (type ee)  */

    if ((ifd = open(ifn, O_RDONLY | O_LARGEFILE)) == -1) {  /*  open input  */
        errsv = errno;
        fprintf(stderr, "The input file '%s' could not be re-opened\n", ifn);
        fprintf(stderr, " errno is '%i - %s'\n", errsv, strerror(errsv));
        exit(4);
    }  /*  end of 'if ((ifd'  */

    if (debug) hexDump("write_MBR_partition entry", (mbr_tbl+i), 16 );

    of = (mbr_tbl+i)->starting_lba;  /*  start of partition  */
    printf("\noffset in sectors= %llu; size in sectors= %lli\n",
            (long long unsigned int) of,
            (long long int) (mbr_tbl+i)->num_sectors);
    of = of * S;  /*  'of' now offset in bytes for 'lseek64'...  */
    printf("offset in bytes = %llu\n", (long long unsigned int) of);

    /*  ----------------------------------------------------  */
    /*  if we are not writing to /dev/null, do the following  */
    /*  ----------------------------------------------------  */
    if ((strcmp(ofn, "/dev/null")) != 0) {
        printf("writing MBR Primary Partition %llu\n", (long long unsigned int) i+1);

        if ((off64t = lseek64(ifd, of, SEEK_SET)) == -1 ) {  /*  point to start of partition  */
            errsv = errno;
            fprintf(stderr, "'lseek64' failed on The input file '%s'; exiting\n", ifn);
            fprintf(stderr, " errno is '%i - %s'\n", errsv, strerror(errsv));
            exit(4);
        }  /*  end of 'if ((off64t'  */

        strcpy(fn, ofn);   /*  copy output filename base  */

        if ((strcmp(ofn, "/dev/null")) != 0) {
            strcat(fn, ".m");  /*  add '.m'                   */
            sprintf(sprintf_buf, "%i", (int) i+1);  /*  find what partition we're copying  */
            strcat(fn, sprintf_buf);          /*  append it to the name  */
            printf("output filename set to %s\n", fn);

            if ((ofd = open(fn, O_WRONLY | O_LARGEFILE | O_CREAT | O_TRUNC, S_IRUSR |
                    S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
                errsv = errno;
                printf("The output file '%s' could not be opened.\n", fn);
                printf(" errno is '%i - %s'\n", errsv, strerror(errsv));
                exit(4);
            }  /*  end of 'if ((ofd = open'  */
        }  /*  end of 'if((strcmp'  */
    }  /*  end of 'if ((strcmp(ofd, "/dev/null"))  */

    progress = 0;
    sectors = (mbr_tbl+i)->num_sectors;
    while (sectors--) {
        /* todo:
            read size s/b at least 128 sectors for efficiency
            warn if set to less than that                     */

        if ((bytes_read = read(ifd, buf, S)) == -1) {
            errsv = errno;
            printf(" errno is '%i - %s'; exiting\n", errsv, strerror(errsv));
            exit(4);
        }  /*  end of 'if ((bytes_read = read'  */

        if (bytes_read != S) {
            printf ("size read, %li, not %i; exiting\n", bytes_read, S);
            exit(4);
        }  /*  end of 'if (bytes_read != S'  */

        if ((progress++ % mod) == 0) {
            printf(".");
            /* todo;
                adjust number of '.'s if read/write more than one sector */
            fflush(stdout);
        }  /*  end of 'if ((progress++'  */

        if ((strcmp(ofn, "/dev/null")) == 0) continue;  /*  don't to the writing part  */

        if ((bytes_written = write(ofd, buf, bytes_read)) == -1) {
            errsv = errno;
            printf(" errno is '%i - %s'; exiting'\n", errsv, strerror(errsv));
            exit(4);
        }  /*  end of 'if ((bytes_written  */

        if (bytes_written != bytes_read) {
            printf("bytes written, %zi, not %zi; exiting\n", bytes_written, bytes_read);
            exit(4);
        }  /*  end of 'if (bytes_written'  */

    }  /*  end of 'while (sectors--'  */

    close(ifd);

    if ((strcmp(ofn, "/dev/null")) == 0) {
        close(ofd);
        return -1;
    }

    return 0;

}

/* --------------------------------------------------------------------------------- */
/*   -----------------------------------------------------------------------------   */
/*   write out the GPT partition to a separate file                                  */
/*   -----------------------------------------------------------------------------   */
/* --------------------------------------------------------------------------------- */
int write_GPT_partition(mbr_ent *mbr_tbl, uint64_t i,
            char *ifn, char *ofn, int mbr_flag, uint64_t start, uint64_t num) {
    int64_t off64t, num_sec, progress, mod=100000;
    int     j, ifd, ofd, errsv, hybrid_flag;
    uint64_t of = 0;
    char    sprintf_buf[4], fn[S+3], buf[S];
    ssize_t bytes_read, bytes_written;

    if ((ifd = open(ifn, O_RDONLY | O_LARGEFILE)) == -1) {
        errsv = errno;
        fprintf(stderr, "The input file '%s' could not be re-opened\n", ifn);
        fprintf(stderr, " errno is '%i - %s'\n", errsv, strerror(errsv));
        exit(4);
    }  /*  end of 'if ((ifd'  */

    /*  ----------------------------------------------------------------  */
    /*  if we are not writing to /dev/null, then do all of the following  */
    /*  ----------------------------------------------------------------  */
    if ((strcmp(ofn, "/dev/null")) != 0) {
        /*  ----------------------------------------------------------------  */
        /*  check to see if there is a matching MBR partition, i.e. a hybrid  */
        /*  ----------------------------------------------------------------  */
        hybrid_flag = 0;
        if (mbr_flag) {
            for (j=0; j<3; j++) {
                if ((mbr_tbl+j)->starting_lba == start &&
                        (mbr_tbl+j)->num_sectors == num) {
                    printf("MBR partition %u matches GPT partition %lu; hybrid\n", j, i);
                    (mbr_tbl+j)->starting_lba = 0;
                    (mbr_tbl+j)->num_sectors = 0;
                    hybrid_flag = 1;
                    continue;
                }  /* end of 'if ((mbr_tbl+j'  */
            }  /*  end of 'for (j=0'  */
        }  /*  end of 'if (mbr_flag)'  */

        printf("\nwriting GPT partition %d\n", (int) i);
        printf("offset (in sectors)= %llu; size (in sectors)= %llu\n",
                (long long unsigned int) start, (long long unsigned int) num);
        start = start*S;    /*  make offset bytes for 'lseek64'...  */

        if ((off64t = lseek64(ifd, start, SEEK_SET)) == -1 ) { /* try to position */
            errsv = errno;
            fprintf(stderr, "'lseek64' failed on The input file '%s'; exiting\n", ifn);
            fprintf(stderr, " errno is '%i - %s'\n", errsv, strerror(errsv));
            exit(4);
        }  /*  end of 'if ((off64t'  */

        strcpy(fn, ofn);   /*  copy output filename base  */
        (hybrid_flag) ? strcat(fn, ".h") : strcat(fn, ".g");   /*  add '.h' or  '.g'  */
        hybrid_flag = 0;  /*  reset the flag  */
        sprintf(sprintf_buf, "%i", (int) i);    /*  find what partition we're copying  */
        strcat(fn, sprintf_buf);          /*  append it to the name  */
        printf("output filename set to %s\n", fn);

        if ((ofd = open(fn, O_WRONLY | O_LARGEFILE | O_CREAT | O_TRUNC, S_IRUSR |
                S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
            errsv = errno;
            printf("The output file '%s' could not be opened.\n", fn);
            printf(" errno is '%i - %s'\n", errsv, strerror(errsv));
            exit(4);
        }  /*  end of 'if ((ofd = open'  */
    }  /*  end of 'if ((strcmp(ofd, "/dev/null")) != 0)  */

    progress = 0;
    while (num--) {
        if ((bytes_read = (read(ifd, buf, S))) == -1) {
            errsv = errno;
            printf(" errno is '%i - %s'\n", errsv, strerror(errsv));
            exit(4);
        }  /*  end of 'if((bytes_read'  */

        if ((progress++ % mod) == 0) {
            printf(".");
            fflush(stdout);
        }  /*  end  of 'if (progress'  */

        if ((strcmp(ofn, "/dev/null")) == 0) continue;

        bytes_read = S;  /*  <---  temp, because 'read' seems to have a bug  ---<<  */

        if ((bytes_written = (write((long int) ofd, buf, S))) == -1) {
            errsv = errno;
            printf(" errno is '%i - %s'\n", errsv, strerror(errsv));
            exit(4);
        }  /*  end of 'if((bytes_written'  */
    }  /*  end of 'while (num--)'  */

    close(ifd);

    if ((strcmp(ofn, "/dev/null")) == 0) {
        close(ofd);
        return -1;
    }

    return 0 ;
}

/* ----------------------------------------------------------------------------------- */
/* 'hexDump' is a function that produces a hex/ascii dump of an area (what a surprise) */
/* ----------------------------------------------------------------------------------- */
void hexDump(char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with lne offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the oddress and offset.
            printf ("  %p  %04x ", addr+i, i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}
