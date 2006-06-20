#!/usr/bin/perl
$file = shift;
open(IN, $file) or die "can't open file";
while( $line = <IN>){
	$i = 0;
	print  $line;
	@num = $line =~ /([^;]*);/g;
	$n = @num;
	print "\$n: $n\n";
	$re = '(.*?);' x ($n-1);
	$re .= '(.*);';
	$line =~ /$re/;
		
	<STDIN>;
}
