#!/usr/bin/perl
#
# Replay a VM run.
#
use English;
use Getopt::Std;
use tt_dom;

my $DEVD	= "ttd-deviced";

my $BASEDIR     =  "/local/sda4";
my $CONFDIR	= "$BASEDIR/xentt";
my $STATEDIR    = "$BASEDIR/xentt-state";

my $DEF_KERNEL  = "$CONFDIR/vmlinuz-2.6.18-xenU";
my $DEF_MEMSIZE	= 64;
my $DEF_LVM	= "";
my $DEF_INITRD  = "$CONFDIR/initrd-2.6.18.8-xenU.img";
my $DEF_RAMDISK	= "$CONFDIR/ramdisk.img";

sub usage()
{
    print STDERR
	"Usage: tt_record [-dfpK] [-s statedir] name\n",
	"  'name'       String identifying the VM\n",
	"  -d           Additional debug output\n",
	"  -f           Force creation\n",
	"  -p           Create it in the paused state\n",
	"  -K           Kill domain (leaves replay state)\n",
	"  -s <dir>     Directory containing replay log and other state\n",
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

my $debug = 0;
my $force = 0;
my $killit = 0;
my $paused = 0;
my $domstate;

my %options = ();
if (!getopts("cdfpKs:", \%options)) {
    usage();
}
$debug = 1 if (defined($options{'d'}));
$force = 1 if (defined($options{'f'}));
$paused = 1 if (defined($options{'p'}));
$killit = 1 if (defined($options{'K'}));
$domstate = $options{'s'} if (defined($options{'s'}));
if (@ARGV < 1) {
    usage();
}
my $name = shift;
if (!defined($domstate)) {
    $domstate = "$STATEDIR/$name";
}

dom_set_debug($debug);

if ($killit) {
    stop_domain($name, $domstate, 0);
    exit(0);
}

if (dom_exists($name)) {
    print STDERR "$name is already running; ".
	"use 'tt_replay -K $name' to kill\n";
    exit(1);
}

my $cfile = "$domstate/xm-replay.conf";
if (!start_domain($name, $domstate, $cfile)) {
    exit(1);
}

exit(0);

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

    #
    # NB: we don't wait for the start, since it may not run long
    # and it could start and die between our checks.
    #
    my $waitforit = $paused ? 1 : 0;

    # and start the domain
    if (!$waitforit) {
	print "WARNING: not waiting for domain to start\n";
    }
    if (!dom_start($name, $cfile, $paused, $waitforit, 0)) {
	dom_stop($name, 1, 0);
	print STDERR "could not start $name\n";
	return 0;
    }

    # record the domid in the statedir
    my $domid = dom_exists($name);
    if (!$domid) {
	dom_stop($name, 1, 0);
	print STDERR "could not find domid for $name!?\n";
	return 0;
    }
    if (open(FD, ">$statedir/domid")) {
	print FD "$domid\n";
	close(FD);
    }

    return 1;
}

sub stop_domain($$$)
{
    my ($name,$statedir,$quiet) = @_;

    if (dom_exists($name)) {
	print STDERR "killing $name...\n" if (!$quiet);
	dom_stop($name, 1, 1);
    }
    run_devd(1, $statedir);

    unlink("$statedir/domid");
}

