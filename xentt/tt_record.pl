#!/usr/bin/perl
#
# Record a VM run.
#
use English;
use Getopt::Std;
use tt_dom;

my $DEVD	= "ttd-deviced";

my $BASEDIR     =  "/local/sda4";
my $CONFDIR	= "$BASEDIR/xentt";
my $STATEDIR    = "$BASEDIR/xentt-state";

my $DEF_KERNEL  = "$CONFDIR/vmlinuz-2.6.18-xenU";
my $DEF_SYMFILE = "$CONFDIR/vmlinux-syms-2.6.18-xenU";
my $DEF_MEMSIZE	= 64;
my $DEF_LVM	= "";
my $DEF_INITRD  = "$CONFDIR/initrd-2.6.18.8-xenU.img";
my $DEF_RAMDISK	= "$CONFDIR/ramdisk.img";

sub usage()
{
    print STDERR
	"Usage: tt_record [-d] [-M mem] [-L lvm] [-R ramdisk] [-s statedir] name\n",
	"  'name'       String identifying the VM\n",
	"  -c           Start up attached to console\n",
	"  -d           Additional debug output\n",
	"  -f           Force creation\n",
	"  -S           Stop recording (destroys domain, leaves state)\n",
	"  -D           Destroy domain (removes all state)\n",
	"  -M <n>       MB of memory to allocate for VM\n",
	"  -L <lvm>     LVM volume with root FS; do not use with -R\n",
	"  -R <ramdisk> initrd disk to use for root FS; do not use with -D\n",
	"  -s <dir>     Directory to write replay log and other state\n",
	"\n";
    exit(1);
}

#
# Untaint the path
# 
$ENV{'PATH'} = "/bin:/usr/bin:/sbin:/usr/sbin";
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

if ($UID) {
    die "Must run as root\n";
}

my $console = 0;
my $debug = 0;
my $force = 0;
my $killit = 0;
my $domstate;

my @TAGS = ('NAME', 'MEM', 'LVM', 'RAMDISK', 'TTOPTS');
my %values = ();
$values{'MEM'} = $DEF_MEMSIZE;
$values{'RAMDISK'} = undef;
$values{'LVM'} = undef;

my %options = ();
if (!getopts("cdfSDM:L:R:s:", \%options)) {
    usage();
}
$console = 1 if (defined($options{'c'}));
$debug = 1 if (defined($options{'d'}));
$force = 1 if (defined($options{'f'}));
$killit = 1 if (defined($options{'S'}));
$killit = 2 if (defined($options{'D'}));
$values{'MEM'} = $options{'M'} if (defined($options{'M'}));
$domstate = $options{'s'} if (defined($options{'s'}));
if (defined($options{'L'})) {
    $values{'LVM'} = $options{'L'};
    $values{'RAMDISK'} = "";
}
if (defined($options{'R'})) {
    $values{'RAMDISK'} = $options{'R'};
    $values{'LVM'} = $initrd = "";    
}
if (@ARGV < 1) {
    usage();
}
$values{'NAME'} = shift;
if (!defined($domstate)) {
    $domstate = "$STATEDIR/" . $values{'NAME'};
}

dom_set_debug($debug);

if (!-d "$STATEDIR") {
    unlink($STATEDIR);
    mkdir($STATEDIR);
}

#
# Kill the record domain
#
if ($killit) {
    if ($killit == 2) {
	destroy_domain($values{'NAME'}, $domstate, 0);
    } else {
	stop_domain($values{'NAME'}, $domstate, 0);
    }
    exit(0);
}

# can only do one
if ($values{'LVM'} && $values{'RAMDISK'}) {
    print STDERR "Can only specify one of -L and -R\n";
    usage();
}

# default to ramdisk if none
if (!$values{'LVM'} && !$values{'RAMDISK'}) {
    $values{'RAMDISK'} = $DEF_RAMDISK;
}

if (-d "$domstate") {
    if (!$force) {
	print STDERR $values{'NAME'}, ": recorded run already exists\n";
	exit(1);
    }
    destroy_domain($name, $domstate, 1);
}
mkdir($domstate); 

#
# If using an LVM, try to create a snapshot of the base provided.
#
if ($values{'LVM'}) {
    if ($values{'LVM'} !~ /^([^\/]+)\/(.*)/) {
	print STDERR "LVM name must be of form <vol-group>/<vol-name>\n";
	exit(1);
    }

    my $snap = "$2.snap";
    if (!make_disk($values{'LVM'}, $snap)) {
	print STDERR "Could not create snapshot of ", $values{'LVM'}, "\n";
	exit(1);
    }

    # record the base name for replay
    if (open(FD, ">$domstate/disk")) {
	print FD $values{'LVM'}, "\n";
	close(FD);
    }

    # domain will use the snapshot
    $values{'LVM'} = $snap;

    # if using lvm, still need a ramdisk, but a "normal" initrd
    $values{'RAMDISK'} = $DEF_INITRD;
}

# add timetravel flags 
$values{'TTOPTS'} = "ttd_flag=1,tt_dir=$domstate";

# XXX record the name of the symbol file for VMI tools
if (open(FD, ">$domstate/symfile")) {
    print FD "$DEF_SYMFILE\n";
    close(FD);
}

my $cfile1 = "$domstate/xm-record.conf";
my $cfile2 = "$domstate/xm-replay.conf";
if (!make_xmconfig($cfile1, $cfile2) ||
    !start_domain($values{'NAME'}, $domstate, $cfile1)) {
    exit(1);
}

print "Recording run of domain; state recorded in $domstate...\n";
exit(0);

sub start_domain($$$)
{
    my ($name,$statedir,$cfile) = @_;

    # see if domain is already running
    if (dom_exists($name)) {
	print STDERR "$name is already running";
	if (!$force) {
	    print STDERR ", quiting\n";
	    return 0;
	}
	print STDERR ", killing\n";
	if (!dom_stop($name, 1, 1)) {
	    print STDERR "$name did not die\n";
	    return 0;
	}
    }

    # restart ttd-deviced
    run_devd(0, $statedir);

    # and start the domain
    if (!dom_start($name, $cfile, 0, 1, $console)) {
	dom_stop($name, 1, 0);
	print STDERR "could not start $name\n";
	return 0;
    }

    return 1;
}

sub stop_domain($$$)
{
    my ($name,$domstate,$quiet) = @_;

    if (dom_exists($name)) {
	print STDERR "killing $name...\n" if (!$quiet);
	dom_stop($name, 1, 1);
    }
    run_devd(1, $domstate);
}

sub destroy_domain($$$)
{
    my ($name,$statedir,$quiet) = @_;

    # kill the domU
    stop_domain($name, $statedir, $quiet);

    # destroy any LVM snapshot
    if (-e "$domstate/disk") {
	my $baselvm = `cat $domstate/disk`;
	chomp($baselvm);

	my $snap = "$baselvm.snap";
	if (!dom_lvm_destroy($snap)) {
	    print STDERR "$name: could not destroy LVM\n" if (!$quiet);
	}
    }

    # remove the state directory
    if (system("rm -rf $statedir")) {
	print STDERR "$name: could not remove old state\n" if (!$quiet);
    }
}

#
# XXX hack: we need to restart deviced every time
#
sub run_devd($$)
{
    my ($killonly,$logdir) = @_;

    my @pids = `pgrep -f $DEVD`;
    if ($? == 0) {
	chomp(@pids);
	print STDERR "killing ttd-deviced pids @pids\n" if ($debug);
	kill(9, @pids);
    }
    if (!$killonly) {
	if (system("$DEVD -f $logdir/ttd.log >>$logdir/ttd.err 2>&1 &")) {
	    die("could not start $DEVD!");
	}
	# XXX give it a second to start up
	sleep(1);
    }
}

#
# Create an xm config file from the template.
# We create one for both record and replay.
# Returns 1 on success, 0 on failure.
#
sub make_xmconfig($$)
{
    my ($recfile,$repfile) = @_;
    my $tfile = "$CONFDIR/xm.conf.template";

    # create new configfiles from the template
    if (!open(CF1, ">$recfile")) {
	print STDERR "could not create record XM config file $recfile\n";
	return 0;
    }
    if (!open(CF2, ">$repfile")) {
	print STDERR "could not create replay XM config file $recfile\n";
	close(CF1);
	return 0;
    }
    if (!open(TF, "<$tfile")) {
	print STDERR "could not open XM template config file $tfile\n";
	close(CF1);
	close(CF2);
	return 0;
    }
    print CF1 "# record config autogenerated from $tfile\n\n";
    print CF2 "# replay config autogenerated from $tfile\n\n";
    while (my $line = <TF>) {
	chomp($line);
	$rline = $line;
	foreach my $tag (@TAGS) {
	    my $tagstr = "%${tag}%";

	    if ($line =~ /($tagstr)/) {
		if (!$values{$tag}) {
		    $line = "#$line";
		    $rline = $line;
		} elsif ($tag eq "TTOPTS") {
		    $line =~ s/$tagstr/$values{$tag}/;
		    $rline =~ s/$tagstr/$values{$tag},tt_replay_flag=1/;
		} else {
		    $line =~ s/$tagstr/$values{$tag}/g;
		    $rline = $line;
		}
		last;
	    }
	}
	print CF1 "$line\n";
	print CF2 "$rline\n";
    }
    close(TF);
    close(CF1);
    close(CF2);

    return 1;
}
