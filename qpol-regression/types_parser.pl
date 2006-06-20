#!/usr/bin/perl
$file = shift;
open(IN, $file) or die "can't open types list file";
while($line = <IN> )
{
	chomp $line;
	if( $line ne "")
	{
		if( $line =~ /^\d+: (.*)/)
		{
			$sp = 0;
			$in_alias = 0;
			$type_attrib_alias = $1;
			$type_attrib_alias =~ /(.*?) (alias .*?\s+)?\(((\d+) attributes)\)/;
			$curr_type = $1;
			push( @ordered_types, $curr_type);
			$found_aliases = $2;
			$num_attr = $4;
			$h_t{$curr_type}{num_attr} = $num_attr;
	
			if($found_aliases =~ /.*{(.*?)}/)
			{
				$aliases = $1;
				$idx = 0;
				@curr_aliases = ();
				while($idx < length($aliases))
				{
					$sub_str = substr($aliases, $idx, length($aliases));
					if( $sub_str =~ /(.*?) /){
						$sub_alias = $1;
					}
					elsif( $sub_str =~ /^(.*)$/ ){
						$sub_alias = $1;
					}
					push(@curr_aliases, $sub_alias); 
					$idx += length($sub_alias)+1;
				}
				$h_t{$curr_type}{num_aliases} = $#curr_aliases + 1;
				@{$h_t{$curr_type}{aliases}}= @curr_aliases;
				$sp = 1;
			}
			else{
				$h_t{$curr_type}{num_aliases} = 0;
			}
			$curr_type = $1;
		}
		elsif( $line =~ /^\s+(.*)/)
		{
			push(@{$h_t{$curr_type}{attribs}},$1);
		}
	}
}
$num_keys = keys %h_t;
$indx= 0;
print "{\n";
foreach $key( @ordered_types )
{
	print "\t{\n\t\t\"$key\",\n\t\t$h_t{$key}{num_attr},\n\t\t{";
	for( $x = 0; $x < @{$h_t{$key}{attribs}}-1; $x++)
	{
		print "\"${$h_t{$key}{attribs}}[$x]\",";
	}
	if( ${$h_t{$key}{attribs}}[$x] ne "")
	{
		print "\"${$h_t{$key}{attribs}}[$x]\"";
	}
	print "},\n";
	print "\t\t$h_t{$key}{num_aliases},";
	print "\n\t\t{";
	for( $x=0; $x < $h_t{$key}{num_aliases} - 1; $x++)
	{
		print "\"${$h_t{$key}{aliases}}[$x]\",";
	}
	if( ${$h_t{$key}{aliases}}[$x] ne "")
	{
		print "\"${$h_t{$key}{aliases}}[$x]\"";
	}
	print "}\n\t}";
	if( $indx < $num_keys )
	{
		print ",\n";
	}
}
