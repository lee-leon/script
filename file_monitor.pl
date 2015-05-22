# The MIT License (MIT)
 
# Copyright (c) 2015 Leon Lee @ lee.leon0519@gmail.com
 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#########################################################################
# File Name   : file_monitor.pl                                                                
# Author      : Leon Lee                                                                            
# Mail        : lee.leon0519@gmail.com                                                                
# Created Time: Fri 31 July 2014 04:32:52 PM CST
# Description : This script monitors files status changes(modified and removed) 
#				in /go1978/portal/ directory and reports who and when did the
#				job to a log file.
#				If there are a lot of files to monitor, you may want to change
#				the limit in /proc/sys/fs/inotify/max_user_watches                                 
#########################################################################
#!/usr/bin/env perl 
#use strict;
#use warnings;
use utf8;
use AnyEvent;
use Linux::Inotify2;
use File::Find;
use File::Basename;
use POSIX;
use File::Tail;
use Time::Local;

my $basename = basename($0);
my $PID_FILE = "/var/run/$basename.pid";
my $sys_audit_log = "/var/log/audit/audit.log";

# Fork this process, to run as a daemon
daemonize();
 
# enable autoflush to have faster logging
$|++;
 
# Catch kill signals
local $SIG{TERM} = sub {
    if(-f $PID_FILE){
        unlink($PID_FILE)
    }
 
    print("$0 daemon killed.");
    exit 0;
};
local $SIG{INT} = $SIG{TERM};
 
my $cv = AnyEvent->condvar;
# watcher container hash
my %W;
 
# Create Inotify object
my $inotify = Linux::Inotify2->new()
    or die "Failed to created inotify object: $!\n";
 
# Search for directories to watch
find({ wanted => sub { -d $_
                       && create_watcher($inotify, $File::Find::name) }  
     }
    , '/go1978/pigcms');
 
 
# Create event loop poller
my $poller = AnyEvent->io(
        fh   => $inotify->fileno,
        poll => 'r',
        cb   => sub { $inotify->poll }
);
 
# Receive event signals (inotify signals)
$cv->recv;
 
#
# Subroutines
#
sub create_watcher {
    my ($inotify, $dir) = @_;
    my $watcher = $inotify->watch($dir, IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO, sub {
            my $e = shift;
            my $filename  = $e->fullname;
             
            if(-d $filename && $e->IN_CREATE) {
                create_watcher($inotify, $filename);
                return
            }
			elsif(-f $filename){
				if($e->IN_MODIFY){
					my $time=&current_time;
					my $file_base = basename($filename);
					my $event_no=&audit_lookup($sys_audit_log,$file_base,1);
					my $uid=&audit_lookup($sys_audit_log,$event_no,2);
					my $uname = getpwuid($uid); 	
					print "$event_no :  $filename modified by $uname on $time\n"
               }
               elsif($e->IN_MOVED_FROM){
					my $time=&current_time;
					my $file_base = basename($filename);
					my $event_no=&audit_lookup($sys_audit_log,$file_base,1);
					my $uid=&audit_lookup($sys_audit_log,$event_no,2);
					my $uname = getpwuid($uid); 	
					print "$event_no :  $filename moved from by $uname on $time\n"
              }
                elsif($e->IN_MOVED_TO){
					my $time=&current_time;
					my $file_base = basename($filename);
					my $event_no=&audit_lookup($sys_audit_log,$file_base,1);
					my $uid=&audit_lookup($sys_audit_log,$event_no,2);
					my $uname = getpwuid($uid); 	
					print "$event_no :  $filename moved from by $uname on $time\n"
               }
                elsif($e->IN_DELETE){
					my $time=&current_time;
					my $file_base = basename($filename);
					my $event_no=&audit_lookup($sys_audit_log,$file_base,1);
					my $uid=&audit_lookup($sys_audit_log,$event_no,2);
					my $uname = getpwuid($uid); 	
					print "$event_no :  $filename removed by $uname on $time\n"
               }
		   }
    });
#    print "Watching $dir\n";
    $W{$dir} = $watcher;
}
 
sub daemonize {
    POSIX::setsid or die "setsid: $!";
    my $pid = fork ();
	if ($pid < 0) {
        die "fork: $!";
    } 
    elsif ($pid) {
        exit 0;
    }
 
    chdir "/";
    umask 0;
    foreach (0 .. (POSIX::sysconf (&POSIX::_SC_OPEN_MAX) || 1024)) { 
        POSIX::close $_
    }
 
    open (STDIN, "/dev/null");
    open (STDOUT, ">>/tmp/piglog.txt");
    open (STDERR, ">&STDOUT");
 
    # Save PID to disk
    open my $pid_file, '>', $PID_FILE
        or die "Could not open PID file: $!\n";
    print { $pid_file } "$$";
    close ($pid_file);
} 


sub current_time {
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
	$year += 1900;
	$mon += 1;
	my $time = "$mday/$mon/$year-$hour:$min:$sec";
	return $time;
}


sub audit_lookup {
	my($file,$patt,$flag) = @_;
	my $filesize = -s $file;
	my $myoffset = -2;
	my @lines = ();
	open F,$file or die "Can't open file\n'";
	while (abs($myoffset) < $filesize) {
		my $line = "";
		while (abs($myoffset) < $filesize) {
			seek F, $myoffset,2;
			$myoffset -=1;
			my $char = getc F;
			last if $char eq "\n";
			$line = $char.$line;
		}
		my ($a,$_,$b)=split(/:/,$line);
		s/[^0-9]//g;
		my $event_no_curr = $_;
		if ($flag eq 1 && $line =~ m/name=\".*$patt\"/) {
			return($event_no_curr);
			exit 1;
		 }
		if ($flag eq 2 && $event_no_curr eq $patt && $line =~ m/.*key=\"td_homeyard\"$/ ) {
			$line =~ /.* (auid)=([0-9]+).*/;
			return($2);
			exit 1;
			}
		}	
}