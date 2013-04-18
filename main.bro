##! Domain generation algorithm infrastructure and detections.
##!
##! Requires: Bro 2.1+
##! Author:   Seth Hall <seth@icir.org>
##! 

@load base/frameworks/notice

module DomainGeneration;

export { 
	## The hour offsets that you would like to generate names for.
	## Domain names for all of the hour offsets specified will be generated.
	const offsets: set[interval] = set(-2hrs,-1hrs,0hrs,1hrs,2hrs) &redef;

	redef enum Notice::Type += {
		## A computed name from a domain generation algorithm was detected.
		Computed_Domain_Detected
	};

	## The "kit" associated with the domain generation algorithm.
	type Kit: enum { EMPTY };

	const domains: table[string] of Kit = table();
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( query in DomainGeneration::domains )
		{
		NOTICE([$note=DomainGeneration::Computed_Domain_Detected,
		        $msg=fmt("%s requested a domain (%s) generated by %s.", c$id$orig_h, query, domains[query]),
		        $sub=cat(domains[query]),
		        $conn=c]);
		}
	}

