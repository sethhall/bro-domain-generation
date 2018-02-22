##! Domain generation algorithm based detection for g01pack.
##!
##! Ported from ruby script found here:
##!     https://gist.github.com/jedisct1/5149014
##! Which was ported from the javascript script found here:
##!     http://www.malwaredomainlist.com/forums/index.php?topic=4962.0
##!
##! Requires: Bro 2.1+
##! Author:   Seth Hall <seth@icir.org>
##! 

@load ./utils

module DomainGeneration;

export { 
	## These are the current names based on the number of hours being offset
	## and calculated.
	global g01pack_current_names: set[string] = set();

	redef enum Kit += { G01PACK };
}

## Domain segments for g01pack.  Probably don't want to touch these.
global g01pack_domains = vector(".doesntexist.com", ".dnsalias.com", ".dynalias.com");
global g01pack_dicts: table[count] of vector of string = table();

function generate_g01pack_name(dict: vector of string, offset: interval): string
	{
	local ts = strftime("%Y %m %d %H", network_time_for_strftime() + offset);
	local parts =  split_string(ts, / /);
	local c0 = to_count(parts[3]);
	local c1 = to_count(parts[2]) + c0;
	local c2 = to_count(parts[1]) + c1 - 1;
	local c3 = to_count(parts[0]) + c2;

	local d0 = c0 % |dict|;
	local d1 = c1 % |dict|;
	local d2 = c2 % |dict|;
	local d3 = c3 % |dict|;

	if ( d0 == d1 )
		d1 = (d1+1) % |dict|;
	if ( d1 == d2 )
		d2 = (d2+1) % |dict|;
	if ( d2 == d3 )
		d3 = (d3+1) % |dict|;

	local domain = g01pack_domains[(c0 % |g01pack_domains|)];
	local subdomain = dict[d0] + dict[d1] + dict[d2] + dict[d3];

	return subdomain + domain;
	}

function generate_g01pack_names(): set[string]
	{
	local results: set[string] = set();
	for ( offset in offsets )
		{
		for ( dict in g01pack_dicts )
			{
			local d = generate_g01pack_name(g01pack_dicts[dict], offset);
			add results[d];
			domains[d] = G01PACK;
			}
		}
	return results;
	}

event update_g01pack_current_names()
	{
	g01pack_current_names = generate_g01pack_names();
	# We don't have a mechanism to schedule things for a certain time yet
	# so we'll just run this every 5 minutes.
	schedule 5mins { update_g01pack_current_names() };
	}

event bro_init()
	{
	g01pack_dicts[1] = vector("t","speed","off","q","ask","why","portal","un","m","is","po","le","us","order","host","na","p","own","call","as","j","o","old","no","si","h","ad","e","r","g","to","cat","n","ko","how","i","tu","l","d","in","on","da","b","ri","f","try","a","k","for","me","net","c","s");
	g01pack_dicts[2] = vector("as","un","si","speed","no","r","in","me","da","a","o","c","try","to","n","h","call","us","why","q","k","old","j","g","how","ri","i","net","t","ko","tu","host","on","ad","portal","na","order","b","ask","l","s","d","po","cat","for","m","off","own","e","f","p","le","is");

	event update_g01pack_current_names();
	}

