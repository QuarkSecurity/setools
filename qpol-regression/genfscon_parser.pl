#!/usr/bin/perl
$file=shift;
open(IN,$file)or die "can't open file";
while( $line=<IN>){
	chomp $line;
	$line =~ /(.*?)\s+(.*?)\s+(.*?)\s+(.*)/;
	$filesystem = $2;
	$path = $3;
	#won't work if mls is more than 1 sensitivity*/
	$4 =~ /(.*?):(.*?):(.*?):(.*)/;
	($hs{$filesystem.":".$path}{user}, $hs{$filesystem.":".$path}{role}, $hs{$filesystem.":".$path}{type}, $hs{$filesystem.":".$path}{mls}) = ($1, $2, $3, $4);
}
$num = keys %hs;
print "$num\n";
<STDIN>;
print "{\n";
foreach $key(keys %hs){
	$key =~ /(.*?):(.*)/;
	$fs = $1;
	$path = $2;
	print "\t{\n\t\t\"$fs\",\n\t\t\"$path\",\n\t\t\"$hs{$fs.\":\".$path}{user}\",\n\t\t\"$hs{$fs.\":\".$path}{role}\",\n\t\t\"$hs{$fs.\":\".$path}{type}\",\n\t\t\"$hs{$fs.\":\".$path}{mls}\"\n\t},\n";
}
