# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

global nets: table[subnet] of string;

event bro_init()
	{
	nets[10.0.0.0/16] = "one";
	nets[192.168.0.0/16] = "two";
	nets[192.168.1.0/24] = "three";
	nets[192.168.4.0/24] = "four";
	nets[192.168.7.0/24] = "five";
	nets[192.168.1.1/32] = "six";

	print "All:";
	for ( net in nets )
		print fmt("%s --> %s", net, nets[net]);
	print "";

	local query = 192.168.1.1/32;
	local result: table[subnet] of string;
	result = lookup_all(nets, query);
	print fmt("Result for %s:", query);
	for ( net in result )
		print fmt("%s --> %s", net, result[net]);
	}
