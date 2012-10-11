#!/usr/bin/perl -w

package tt_dom;
use Exporter;
@ISA = "Exporter";
@EXPORT = qw ( dom_exists dom_status dom_start dom_stop dom_set_debug
	       dom_lvm_exists dom_lvm_snapshot dom_lvm_destroy );

use English;

my $debug = 0;

sub dom_set_debug($)
{
    $debug = shift;
}

#
# See if a domain exists and returns its ID
# Returns zero on failure (so don't ask for "Domain-0"!)
#
sub dom_exists($)
{
    my $dom = shift;

    my @out = `xm list 2>&1`;
    foreach my $l (@out) {
	if ($l =~ /^Name\s+/) {
	    next;
	}
	if ($l =~ /^(\S+)\s+(\d+)/) {
	    if ($1 eq $dom) {
		return $2;
	    }
	}
    }

    return 0;
}

#
# Return the status info for a Xen domain.
# A null string indicates an error.
#
sub dom_status($)
{
    my ($id) = @_;

    my $status = `xm list --long $id 2>/dev/null`;
    if ($status =~ /\(state ([\w-]+)\)/) {
        return $1;
    }
    return "";
}

#
# Start up a domain and wait til it is "up".
# Returns 1 on success, 0 otherwise.
#
sub dom_start($$$$$)
{
    my ($name,$cfile,$paused,$waitfor,$console) = @_;

    print STDERR "Starting dom $name\n" if ($debug);

    my $opts = $paused ? "-p" : "";
    my $redir = $debug ? "" : "1>/dev/null 2>&1";
    if ($console) {
	$opts .= " -c";
	$redir = "";
    }

    if (system("xm create $cfile $opts $redir")) {
	print STDERR "'xm create $cfile $opts $redir' failed\n";
	return 0;
    }

    return 1 if (!$waitfor || $console);

    # Spend 30 seconds waiting for the Xen domain to boot
    my $stat = "";
    for (1..15) {
	sleep(2);
	$stat = dom_status($name);
	print STDERR "xm stat=$stat\n"
	    if ($debug);
	if ($stat) {
	    if ($stat =~ /b/) {
		# booted: call it good
		return 1 if (!$paused);
	    } elsif ($stat =~ /p/) {
		# paused: make be good if that is what we want
		return 1 if ($paused);
	    } elsif ($stat =~ /c/) {
		# crashed: never a good thing
		print STDERR "$name crashed\n";
		return 0;
	    }
	}
    }

    print STDERR "$name did not start after 30 seconds, xm status=$stat\n";
    return 0;
}

#
# Shutdown or destroy a domain.
# Returns 1 on success, 0 on failure.
#
sub dom_stop($$$)
{
    my ($name,$destroy,$waitfor) = @_;
    my $cmd;

    if ($destroy) {
	print STDERR "Destroying VM $name\n" if ($debug);
	$cmd = "destroy";
    } else {
	print STDERR "Shutting down VM $name\n" if ($debug);
	$cmd = "shutdown";
    }
    my $redir = $debug ? "" : "1>/dev/null 2>&1";
    if (system("xm $cmd $name $redir")) {
	print STDERR "'xm $cmd $name $redir' failed\n" if ($debug);
	return 0;
    }

    return 1 if (!$waitfor);

    # Spend 20 seconds waiting for the Xen domain to disappear
    my $stat = "";
    for (1..20) {
	sleep(1);
	$stat = dom_status($name);
	print STDERR "xm stat=$stat\n" if ($debug);
	if (!$stat) {
	    return 1;
	}
    }

    print STDERR "$name did not die after 20 seconds, xm status=$stat\n"
	if ($debug);
    return 0;
}


sub dom_lvm_exists($)
{
    my ($lvm) = @_;

    @out = `lvs --noheadings 2>&1`;
    foreach my $l (@out) {
	if ($l =~ /^\s+(\S+)\s+/) {
	    if ($lvm eq $1) {
		return 1;
	    }
	}
    }

    return 0;
}

sub dom_lvm_snapshot($$)
{
    my ($base,$snap) = @_;

    if (!dom_lvm_exists($base)) {
	print STDERR "$base LVM does not exist\n";
	return 0;
    }
    if (dom_lvm_exists($snap)) {
	print STDERR "$snap snapshot LVM already exists\n";
	return 0;
    }
    if (system("lvcreate -s -L 1000M -n $snap $base")) {
	print STDERR "$base: could not create snapshot $snap\n";
	return 0;
    }

    return 1;
}

sub dom_lvm_destroy($)
{
    my ($lvm) = @_;

    if (system("lvremove -f $lvm")) {
	print STDERR "$lvm: could not destroy\n";
	return 0;
    }

    return 1;
}

1;
