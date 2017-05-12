#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use File::Basename;
use Getopt::Std;
use File::Copy;

####
#
# BMC Software
# Matthew J. Salerno
# -
# Bulk Scan File upload
#
####

####
# NOTES
#
# I know I shouldn't use regex to parse JSON
# I'm trying to reduce the module dependencies
# to keep it portable.
#
# Not sure if I should loop on all failed tasks
# at end of script to re-check their status
#
####

# VARS TO BE CLEANED UP
#$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

my $loginurl = 'https:// /dcaportal/api/login';
my $scanuploadurl = 'https:// /dcaportal/api/vulnerability/importScan';
my $statuscheckurl = 'https:// /dcaportal/api/bsmsearch/results?taskId=';

my $importsev;
my @failedtasks;

# Associate scan file extension with scanner
my %scanengines = (
        "qualys" => "xml",
        "rapid7" => "xml",
        "nessus" => "nessus"
);

# Define Severities - convert to proper string
my %severities = (
	1 => "Severity 1",
	2 => "Severity 2",
	3 => "Severity 3",
	4 => "Severity 4",
	5 => "Severity 5"
);

# Define Auth modes
my %auth = (
	sccm => q|{"authenticationMethod":"SRP", "username": "##USERNAME##", "password":"##PASSWORD##"}|,
	bsa =>  q|{"authenticationMethod":"SRP", "username": "##USERNAME##", "password":"##PASSWORD##"}|
);

# Declare the perl command line options
my %options=();
getopts("u:p:v:s:d:a:", \%options);

# Declare the required options
my @required = qw(u p v d a);

my $help = q|
Required Options:
-a     Auth mode (BSA,SCCM)
-u     Username
-p     Password
-v     Scan Vendor (Qualys,Rapid7,Nessus)
-d     Scan file directory path
-s     Comma-separated list of Severities to import (default: 3,4,5)

|;

# Sanity check on Options
foreach (@required){
	if (!exists $options{$_}){
		print $help;
		print "Missing Option: -$_\n";
		exit;
	}
}

# Check scan vendor
if (!exists $scanengines{lc($options{v})}){
	print $help;
	print "Invalid Scan vendor specified: $options{v}\n";
	exit;
}
my $scanvendor = ucfirst(lc($options{v}));

# Check auth method
if (!exists $auth{lc($options{a})}){
        print $help;
        print "Invalid Auth method specified: $options{a}\n";
        exit;
}

# Check severity
if (exists($options{s}) ){
	my @sevs = split(/,/, $options{s});
	foreach my $sev (@sevs){
		$sev =~ s/\s//g;
		if (!exists $severities{$sev}){
			print $help;
			print "Invalid Severity defined: $sev\n";
			exit;
		}
		$importsev .= "Severity $sev,";
	}
	chop $importsev;
}
else {
	$importsev = 'Severity 3,Severity 4,Severity 5';
}

# Validate source directory
# Create directories
my @dirstatus = dircheck($options{d});
if ($dirstatus[0] != 0){
	print $help;
	print "$dirstatus[1]\n";
	exit;
}

# Get a list of scan files
my @scanfiles = getscans($options{d}, $scanengines{lc($scanvendor)});

if (!@scanfiles){
	print "No scan files locaated at: $options{d}\n";
	exit 0;
}

# Build the auth string
(my $loginstr = $auth{lc($options{a})}) =~ s/##USERNAME##/$options{u}/g;
$loginstr =~ s/##PASSWORD##/$options{p}/g;

####
#
# Build the web object
#
###

my $ua = LWP::UserAgent->new();
$ua->cookie_jar( {} );

# Authenticate
my ($status, $clientid) = login($ua, $loginurl, $loginstr);
if ($status != 0){
	print "Authentication Error: $clientid\n";
	exit 1;
}

foreach my $file (@scanfiles){
	my $fullfilepath = $options{d}."/".$file;
	print "$file: Uploading $fullfilepath\n";
	my ($status,$httpreturn) = uploadscan($ua, $clientid, $scanuploadurl, $fullfilepath,$importsev,$scanvendor);
	print "$file: Upload Complete: $httpreturn\n";
	if ($status != 0){
		print "$file: $httpreturn\n";
		exit 1;
	}
	my ($taskid) = $httpreturn =~ m/.*taskId":"(.*?)".*/g;
	my ($taskstatus,$taskreturn) = checktask($ua,$clientid,$statuscheckurl,$taskid);
	$taskreturn =~ s|^|$file: |mg;
	print $taskreturn."\n";

	my $newfile = $file;
	if ($taskstatus == 0){
		if (-f "$options{d}/imported/$file"){
			my $epoch = time;
			move($fullfilepath,"$options{d}/imported/$file-$epoch") or warn "$file: Move failed: $!";
			print "$file: Moved to $options{d}/imported/$file-$epoch\n";
		}
		else {
			move($fullfilepath,"$options{d}/imported/$file") or warn "$file: Move failed: $!";
			print "$file: Moved to $options{d}/imported/$file\n";
		}
	}
	else {
		push (@failedtasks, $taskid); # Should we maybe check these one more time before declaring it a failure?
		if (-f "$options{d}/failed/$file"){
			my $epoch = time;
			move($fullfilepath,"$options{d}/failed/$file-$epoch") or warn "$file: Move failed: $!" && next;
			print "$file: Moved to $options{d}/failed/$file-$epoch\n";
		}
		else {
			move($fullfilepath,"$options{d}/failed/$file") or warn "$file: Move failed: $!" && next;
			print "$file: Moved to $options{d}/failed/$file\n";
		}
	}
}
exit 0;

sub dircheck {
	my $scanfiledir = shift;
	if (!-d $scanfiledir){
		return (1, "Directory does not exist: $scanfiledir");
	}
	if (!-d "$scanfiledir/imported"){
		mkdir "$scanfiledir/imported" or return (1, "Cannot create directory: $scanfiledir/uploaded $!\n");
	}
	if (!-d "$scanfiledir/failed"){
		mkdir "$scanfiledir/failed" or return (1, "Cannot create directory: $scanfiledir/failed $!\n");
	}
	return 0;
}

sub getscans {
	my $scanfiledir = shift;
	my $scanext = shift;
	opendir my $scanfh, $scanfiledir or die "Cannot open directory: $!";
	my @scans = grep(/\.$scanext$/i,readdir($scanfh));
	closedir $scanfh;
	return @scans;
}

sub uploadscan {
	my $ua = shift;
	my $clientid = shift;
	my $scanuploadurl = shift;
	my $scanfile = shift;
	my $importsev = shift;
	my $scanvendor = shift;
	my $scanfilename = basename $scanfile;

	my $uploadreq = POST $scanuploadurl,
	[
	$scanfilename => ["$scanfile", undef, "Content-Type" => "text/xml"],
	osTobeConsidered => 'Linux,Windows',
	severitiesTobeConsidered => $importsev,
	selectedVendor => $scanvendor
	],
	Content_Type => 'form-data';
	
	$uploadreq->header(ClientId => $clientid);

	#$ua->prepare_request($uploadreq);
	#print($uploadreq->as_string);
	#my $upresponse = $ua->send_request($uploadreq);
	#print $upresponse->as_string;
	
	my $upresponse = $ua->request($uploadreq);
	if ($upresponse->is_success) {
		return (0,$upresponse->decoded_content);
	}
	else {
		return (1,"Error: " . $upresponse->status_line . "\n");
	}
}

sub login {
	my $ua = shift;
	my $loginurl = shift;
	my $loginstr = shift;
	my $loginreq = HTTP::Request->new( POST => $loginurl);
	$loginreq->content_type('application/json');
	$loginreq->content($loginstr);
	my $loginres = $ua->request($loginreq);

	if ($loginres->is_success) {
		my ($errorcode) = $loginres->decoded_content =~ m/.*errorCode":"?(.*?)"?,.*/g;
		if ($errorcode =~ /null/i){
			($clientid) = $loginres->decoded_content =~ m/.*clientId":"(.*?)".*/g;
			return (0,$clientid);
		}
		else {
			return (1,$errorcode);
		}
	}
	else {
		return (1,$loginres->status_line);
	}
}

sub checktask{
	my $ua = shift;
	my $clientID = shift;
	my $statuscheckurl = shift;
	my $taskid = shift;

	my $taskreq = HTTP::Request->new( GET => $statuscheckurl.$taskid);
	$taskreq->header(ClientId => $clientid);
	my $taskres = $ua->request($taskreq);

	my ($errorcode) = $taskres->decoded_content =~ m/.*errorCode":"?(.*?)"?,.*/g;

	if ($errorcode =~ /null/i){
		return (0, "Status: Import successful");
	}
	else {
		my ($errorcause) = $taskres->decoded_content =~ m/.*errorCause":"(.*?)".*/g;
		my ($taskprogress) = $taskres->decoded_content =~ m/.*taskProgress":(.*?),.*/g;
		my ($taskstate) = $taskres->decoded_content =~ m/.*taskState":"(.*?)".*/g;
		my $returnstat = "Status: $taskstate\nCode: $errorcode\nCause: $errorcause";
		return (1, $returnstat);
	}
}
