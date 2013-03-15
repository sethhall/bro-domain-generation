##! Domain generation algorithm based detection for g01pack.
##!
##! Ported from ruby script found here:
##!     https://gist.github.com/jedisct1/5149014
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

	## Domain segments for g01pack.  Probably don't want to touch these.
	const g01pack_domains = vector(".doesntexist.com", ".dnsalias.com", ".dynalias.com") &redef;
	## Subdomain segments for g01pack.  Probably don't want to touch these.
	const g01pack_dict = vector("as","un","si","speed","no","r","in","me","da","a","o","c","try","to","n","h","call","us","why","q","k","old","j","g","how","ri","i","net","t","ko","tu","host","on","ad","portal","na","order","b","ask","l","s","d","po","cat","for","m","off","own","e","f","p","le","is") &redef;

	redef enum Kit += { G01PACK };
}

function generate_g01pack_name(offset: interval): string
	{
	local ts = strftime("%Y %m %d %H", network_time_for_strftime() + offset);
	local parts =  split(ts, / /);
	local c0 = to_count(parts[4]);
	local c1 = to_count(parts[3]) + c0;
	local c2 = to_count(parts[2]) + c1 - 1;
	local c3 = to_count(parts[1]) + c2;

	local d0 = c0 % |g01pack_dict|;
	local d1 = c1 % |g01pack_dict|;
	local d2 = c2 % |g01pack_dict|;
	local d3 = c3 % |g01pack_dict|;

	if ( d0 == d1 )
		d1 = (d1+1) % |g01pack_dict|;
	if ( d1 == d2 )
		d2 = (d2+1) % |g01pack_dict|;
	if ( d2 == d3 )
		d3 = (d3+1) % |g01pack_dict|;

	local domain = g01pack_domains[(c0 % |g01pack_domains|)];
	local subdomain = g01pack_dict[d0] + g01pack_dict[d1] + g01pack_dict[d2] + g01pack_dict[d3];

	return subdomain + domain;
	}

function generate_g01pack_names(): set[string]
	{
	local results: set[string] = set();
	for ( offset in offsets )
		{
		local d = generate_g01pack_name(offset);
		add results[d];
		domains[d] = G01PACK;
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
	event update_g01pack_current_names();
	}

