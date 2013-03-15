
module DomainGeneration;

function localtime_offset(): interval
	{
	local tz = strftime("%z", network_time());
	local i = 1;
	local negative=F;
	if ( sub_bytes(tz,i,1) == "-" )
		{
		++i;
		negative=T;
		}

	local seconds = (to_int(sub_bytes(tz,i,2))*60*60) + (to_int(sub_bytes(tz,i+2,2))*60);
	return double_to_interval((negative?-1:1)*seconds);
	}

function network_time_for_strftime(): time
	{
	return network_time()-localtime_offset();
	}