#!/usr/bin/perl

use strict;

my $f = 0;
while (my $line = <STDIN>) {
    # keep all the current imports
    if ($line =~ /\s*<import /) {
	if ($f == 0) {
	    # print all the extra imports
	    for my $arg (@ARGV) {
		my ($ns,$loc) = split(/::/,$arg);
		if ($ns ne '' && $loc ne '') {
		    print "  <include schemaLocation=\"$loc\"/>\n";
		}
	    }
	}
	$f = 1;
	print $line;
    }
    elsif ($f == 1) {
	# skip all the lines until the xml schema for operation msgs.
	if ($line =~ /\s*<!-- operation /) {
	    $f = 0;
	    print $line;
	}
    }
    else {
	print $line;
    }
}

exit 0;
