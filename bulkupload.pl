#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use File::Basename;
use Getopt::Std;
use File::Copy;

use Data::Dumper;
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
$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

my $loginurl = 'https://secure.secops.bmc.com/dcaportal/api/login';
my $scanuploadurl = 'https://secure.secops.bmc.com/dcaportal/api/vulnerability/importScan';
my $statuscheckurl = 'https://secure.secops.bmc.com/dcaportal/api/bsmsearch/results?taskId=';


my @failedtasks;

my %runningtasks; # Used for long running tasks

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
my $importsev;
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
	print "No scan files located at: $options{d}\n";
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
my ($loginreturn) = login($ua, $loginurl, $loginstr);
if (exists $$loginreturn{'errormsg'}){
	print "HTTP Status: $$loginreturn{'HTTPCode'} $$loginreturn{'HTTPMessage'}\n";
	print "$$loginreturn{'errormsg'}\n";
	exit 1;
}

foreach my $file (@scanfiles){
	my $fullfilepath = $options{d}."/".$file;
	print "$file: Uploading $fullfilepath\n";
	my ($uploadreturn) = uploadscan($ua, $$loginreturn{'clientId'}, $scanuploadurl, $fullfilepath,$importsev,$scanvendor);

	if (exists $$uploadreturn{'errormsg'}){
		print "$file: HTTP Status: $$uploadreturn{'HTTPCode'} $$uploadreturn{'HTTPMessage'}\n";
		print "$file: $$loginreturn{'errormsg'}\n";
		exit 1;
	}

	if (exists $$uploadreturn{'taskId'}){
		sleep 1;
		my $taskreturn = checktask($ua,$$loginreturn{'clientId'},$statuscheckurl,$$uploadreturn{'taskId'});	

		if ($$taskreturn{'completed'} =~ /false/i && $$taskreturn{'taskProgress'} != 100.0){
			print "$file: Task still processing - Putting in queue and not moving file for now\n";
			$runningtasks{$$uploadreturn{'taskId'}} = $file;
			next;
		}
		if (exists $$taskreturn{'errormsg'}){
			$$taskreturn{'errormsg'} =~ s|^|$file: |mg;
			print "$file: HTTP Status: $$taskreturn{'HTTPCode'} $$taskreturn{'HTTPMessage'}\n";
			print "$$taskreturn{'errormsg'}\n";
		}
		my $movestatus = movefile($file,$options{d},$$taskreturn{'errorCode'});
		print "$file: $movestatus\n";
	}
}
exit 0;

sub movefile {
	my $file = shift;
	my $path = shift;
	my $errorCode = shift;

	my $fullfilepath = $path."/".$file;

	my $newfile = $file;
	if ($errorCode =~ /null/i ){
		if (-f "$path/imported/$file"){
			my $epoch = time;
			move($fullfilepath,"$path/imported/$file-$epoch") or return "$file: ERROR: Move failed: $!";
			return "$file: Moved to $path/imported/$file-$epoch\n";
		}
		else {
			move($fullfilepath,"$path/imported/$file") or return "$file: ERROR: Move failed: $!";
			return "$file: Moved to $path/imported/$file\n";
		}
	}
	else {
		#push (@failedtasks, $$uploadreturn{'taskId'}); # Should we maybe check these one more time before declaring it a failure?
		if (-f "$path/failed/$file"){
			my $epoch = time;
			move($fullfilepath,"$options{d}/failed/$file-$epoch") or return "$file: ERROR: Move failed: $!";
			return "$file: Moved to $path/failed/$file-$epoch\n";
		}
		else {
			move($fullfilepath,"$path/failed/$file") or return "$file: ERROR: Move failed: $!";
			return "$file: Moved to $path/failed/$file\n";
		}
	}
}

	

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
	
	my $uploadres = $ua->request($uploadreq);

	my $uploadreturn = parseOutput($uploadres);
	return $uploadreturn;
}

sub login {
	my $ua = shift;
	my $loginurl = shift;
	my $loginstr = shift;
	my $loginreq = HTTP::Request->new( POST => $loginurl);
	$loginreq->content_type('application/json');
	$loginreq->content($loginstr);
	my $loginres = $ua->request($loginreq);
	
	my $httpreturn = parseOutput($loginres);
	return $httpreturn;
}

sub checktask{
	my $ua = shift;
	my $clientID = shift;
	my $statuscheckurl = shift;
	my $taskid = shift;

	my $taskreq = HTTP::Request->new( GET => $statuscheckurl.$taskid);
	$taskreq->header(ClientId => $clientID);
	my $taskres = $ua->request($taskreq);

	my $taskreturn = parseOutput($taskres);
	return $taskreturn;
}

sub parseOutput {
	my $response = shift;
	my %responsedata;

	$responsedata{'HTTPCode'} = $response->code;

	$responsedata{'HTTPMessage'} = $response->message;
	$responsedata{'Content'} = $response->decoded_content;

	if ($responsedata{'HTTPCode'} != 200){
		$responsedata{errormsg} .= "HTTP Response: Invalid\n";
	}

	if ($responsedata{'Content'} =~ /taskId/){
		($responsedata{'taskId'}) = $response->decoded_content =~ m/.*taskId":"(.*?)".*/g;
	}

	if ($responsedata{'Content'} =~ /errorCode/){
		($responsedata{'errorCode'}) = $response->decoded_content =~ m/.*errorCode":"?(.*?)"?,.*/g;
		if ($responsedata{'errorCode'} !~ /null/i){
			$responsedata{errormsg} .= "Code: $responsedata{'errorCode'}\n";
		}
	}

	if ($responsedata{'Content'} =~ /errorCause/){
		($responsedata{'errorCause'}) = $response->decoded_content =~ m/.*errorCause":"(.*?)".*/g;
		$responsedata{errormsg} .= "Cause: $responsedata{'errorCause'}\n";
	}

	if ($responsedata{'Content'} =~ /taskProgress/){
		($responsedata{'taskProgress'}) = $response->decoded_content =~ m/.*taskProgress":(.*?),.*/g;
		$responsedata{errormsg} .= "Progress: $responsedata{'taskProgress'}\n";
	}

	if ($responsedata{'Content'} =~ /taskState/){
		($responsedata{'taskState'}) = $response->decoded_content =~ m/.*taskState":"(.*?)".*/g;
		$responsedata{errormsg} .= "App Status: $responsedata{'taskState'}\n";
	}

	if ($responsedata{'Content'} =~ /clientId/){
		($responsedata{'clientId'}) = $response->decoded_content =~ m/.*clientId":"(.*?)".*/g;
	}

	if ($responsedata{'Content'} =~ /completed/){
		($responsedata{'completed'}) = $response->decoded_content =~ m/.*completed":"?(.*?)"?,.*/g;
	}

	return \%responsedata;
}
