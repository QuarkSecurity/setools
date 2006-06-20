#!/usr/bin/perl 
$file = shift;
open( IN, $file ) or die "can't open file: $file\n";
while( $line = <IN> ) {
	chomp $line;
	if( $line =~ /(.*?)\s+Default State: (.*?)\s+Current State: (.*?)/){
		$bool_name = $1;
		if( $2 eq "True" ){
			$h_bools{$bool_name}{VALUE} = 1;
		}
		else{
			$h_bools{$bool_name}{VALUE} = 0;
		}
	}
}
print "{\n";
foreach $bool_name ( keys %h_bools ){
	print "\t{\n\t\t\"$bool_name\",\n\t\t$h_bools{$bool_name}{VALUE},\n\t},\n";
}
