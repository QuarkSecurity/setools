#!/usr/bin/perl 
open IN, "parse_perm";
$num_classes = 0;
while( <IN> )
{
	if( $_ =~ /^\w+$/ )
	{
		$_ =~ /(\w+)/;
		$curr_class = $1;
		$num_classes ++;
	}
	else{
		$_ =~ /^\s+(.*)$/;
		$l = $1;
		if( $l =~ /(.*?)  \(.*?\)/)
		{
			$t_1 = $1;
		}
		else{ $t_1 = $l; }
		push @{$C_P_h{$curr_class}}, $t_1;
	}
}
if( 0 ){
foreach $key (keys %C_P_h ){
	$n = @{$C_P_h{$key}};
	$n--;
	print "{\n\t$n,\n\t\"$key\",\n\t{";	
	$i = @{$C_P_h{$key}};
	$i--;
	for( $g = 0; $g < $i-1; $g++)
	{
		print "\"${$C_P_h{$key}}[$g]\"\,";
	}
	print "\"${$C_P_h{$key}}[$g]\"}\n";
	print "},\n";
}
}
foreach $key (keys %C_P_h ){
	print "\"$key\",\n";
}
