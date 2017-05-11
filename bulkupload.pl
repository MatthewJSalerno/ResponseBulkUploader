#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use File::Basename;
use Getopt::Std;

####
# TODO
#
# Check response of uploaded file - Duplicate file check / Invalid parsing
# Move files to directory based on response
#
####


# TEMP VARS TO BE CLEANED UP
$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;
my $loginurl = 'https://  /dcaportal/api/login';
my $scanuploadurl = 'https:// /dcaportal/api/vulnerability/importScan';

my $importsev;

# BMC Software
# Matthew Salerno
# -
# Bulk Scan File upload
#
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
	print "Invalid scan vendor specified: $options{v}\n";
	exit;
}
my $scanvendor = ucfirst(lc($options{v}));

# Check auth method
if (!exists $auth{lc($options{a})}){
        print $help;
        print "Invalid auth method specified: $options{a}\n";
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
	print $clientid."\n";
	exit 1;
}

foreach my $file (@scanfiles){
	my $fullfilepath = $options{d}."/".$file;
	print "Uploading $fullfilepath\n";
	my $uploadstatus = uploadscan($ua, $clientid, $scanuploadurl, $fullfilepath,$importsev,$scanvendor);
	print "Upload Complete: $uploadstatus\n\n";
}
exit;

sub dircheck {
	my $scanfiledir = shift;
	if (!-d $scanfiledir){
		return (1, "Directory does not exist: $scanfiledir");
	}
	if (!-d "$scanfiledir/uploaded"){
		mkdir "$scanfiledir/uploaded" or return (1, "Cannot create directory: $scanfiledir/uploaded $!\n");
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
	my @scans = grep(/\.$scanext$/,readdir($scanfh));
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
		return $upresponse->decoded_content;
	}
	else {
		return "Error: " . $upresponse->status_line . "\n";
	}
}

sub login {
	my $ua = shift;
	my $loginurl = shift;
	my $loginstr = shift;
	my $req = HTTP::Request->new( POST => $loginurl);
	$req->content_type('application/json');
	$req->content($loginstr);
	my $res = $ua->request($req);

	if ($res->is_success) {
		if ($res->decoded_content =~ /BAD_CREDENTIALS_AUTHENTICATION_FAILURE/i){
			return (1,"BAD_CREDENTIALS_AUTHENTICATION_FAILURE");
		}
		else {
			($clientid) = $res->decoded_content =~ m/.*clientId":"(.*)".*/g;
			return (0,$clientid);
		}
	}
	else {
		return (1,$res->status_line);
	}
}
