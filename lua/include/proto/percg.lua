------------------------------------------------------------------------
--- @file percg.lua
--- @brief PERC generic protocol utility.
--- Utility functions for the percg_header structs 
--- defined in \ref headers.lua . \n
--- Includes:
--- - PERCG constants
--- - PERCG header utility
--- - Definition of PERCG packets
------------------------------------------------------------------------

local ffi = require "ffi"
local pkt = require "packet"

require "utils"
require "headers"

local ntoh, hton = ntoh, hton
local ntoh16, hton16 = ntoh16, hton16
local bswap = bswap
local bswap16 = bswap16
local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift
local istype = ffi.istype
local format = string.format

----------------------------------------------------------------------------------
---- PERC Generic constants
----------------------------------------------------------------------------------

--- PERC Generic protocol constants
local percg = {}

--- isData field value for Control
percg.PROTO_CONTROL	= 0x00
percg.PROTO_DATA = 0x01


----------------------------------------------------------------------------------
---- PERC addresses (nothing special)
----------------------------------------------------------------------------------


-----------------------------------------------------------------------------------
---- PERC Generic header
-----------------------------------------------------------------------------------

--- Module for percg_header struct (see \ref headers.lua).
local percgHeader = {}

percgHeader.__index = percgHeader

--- Set the source.
--- @param int source of percg header as 8 bit integer.
function percgHeader:setSource(int)
	int = int or 0 
	self.source = int
end

--- Set the destination.
--- @param int destination of percg header as 8 bit integer.
function percgHeader:setDestination(int)
	int = int or 0 
	self.destination = int
end

--- Set the preamble.
--- @param int preamble of percg header as 16 bit integer. Should always be '0x5555'
function percgHeader:setPreamble(int)
	int = int or 0 
	self.preamble = hton16(0x5555)
end

--- Set the isData field.
--- @param int isData of percg header as 8 bit integer.
function percgHeader:setIsData(int)
	int = int or percg.PROTO_DATA
	self.isData = int
end

--- Set the flowId.
--- @param int flowId of percg header as 8 bit integer.
function percgHeader:setFlowId(int)
	int = int or 0 
	self.flowId = int
end

--- Retrieve the source. 
--- @return Source as 8 bit integer.
function percgHeader:getSource()
	return self.source
end

--- Retrieve the destination. 
--- @return Destination as 8 bit integer.
function percgHeader:getDestination()
	return self.destination
end


--- Retrieve the isData field. 
--- @return IsData as 8 bit integer.
function percgHeader:getIsData()
	return self.isData
end

--- Retrieve the flowId. 
--- @return FlowId as 8 bit integer.
function percgHeader:getFlowId()
	return self.flowId
end

--- Retrieve the preamble. 
--- @return Preamble as 16 bit integer.
function percgHeader:getPreamble()
	return ntoh16(self.preamble)
end


--- Retrieve isData. 
--- @return isData as string.
function percgHeader:getIsDataString()
	local proto = self:getIsData()
	local cleartext = ""
	
	if proto == percg.PROTO_CONTROL then
		cleartext = "(CONTROL)"
	elseif proto == percg.PROTO_DATA then
		cleartext = "(DATA)"
	else
		cleartext = "(unknown)"
	end
	
	return format("0x%02x %s", proto, cleartext)
end



--- Set all members of the percg header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: Preamble, Source, Destination, IsData, FlowId 
--- @param pre prefix for namedArgs. Default 'percg'.
--- @code
--- fill() --- only default values
--- fill{ percgSource=0, percgFlowId=5 } --- all members are set to default values with the exception of percgSource and percgFlowId
--- @endcode
function percgHeader:fill(args, pre)
	args = args or {}
	pre = pre or "percg"
	
	self:setPreamble(args[pre .. "Preamble"])
	self:setSource(args[pre .. "Source"])
	self:setDestination(args[pre .. "Destination"])
	self:setIsData(args[pre .. "IsData"])
	self:setFlowId(args[pre .. "FlowId"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'percg'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see percgHeader:fill
function percgHeader:get(pre)
	pre = pre or "percg"

	local args = {}
	args[pre .. "Preamble"] = self:getPreamble()
	args[pre .. "Source"] = self:getSource()
	args[pre .. "Destination"] = self:getDestination()
	args[pre .. "IsData"] = self:getIsData()
	args[pre .. "FlowId"] = self:getFlowId()
	return args	
end

--- Retrieve the values of all members.
--- @return Values in string format.
function percgHeader:getString()
	return "PERCG " .. self:getSource() .. " > " .. self:getDestination() .. " isData " .. self:getIsDataString() 
		   .. " flowId " .. self:getFlowId()
end

-- Maps headers to respective protocol value.
-- This list should be extended whenever a new protocol is added to 'PERCG constants'. 
local mapNameProto = {
      control = percg.PROTO_CONTROL,
      data = percg.PROTO_DATA,
}

--- Resolve which header comes after this one (in a packet).
--- For instance: in tcp/udp based on the ports.
--- This function must exist and is only used when get/dump is executed on
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'udp', 'icmp', nil)
function percgHeader:resolveNextHeader()
	local proto = self:getIsData()
	for name, _proto in pairs(mapNameProto) do
		if proto == _proto then
			return name
		end
	end
	return nil
end

--- Change the default values for namedArguments (for fill/get).
--- This can be used to for instance calculate a length value based on the total packet length.
--- See proto/ip4.setDefaultNamedArgs as an example.
--- This function must exist and is only used by packet.fill.
--- @param pre The prefix used for the namedArgs, e.g. 'percg'
--- @param namedArgs Table of named arguments (see See Also)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see percgHeader:fill
function percgHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	-- TODO(lav): not sure if this is relevant to PERCG
	-- set length
	-- if not namedArgs[pre .. "Length"] and namedArgs["pktLength"] then
	--	namedArgs[pre .. "Length"] = namedArgs["pktLength"] - accumulatedLength
	-- end
	
	-- set protocol
	if not namedArgs[pre .. "IsData"] then
		for name, type in pairs(mapNameProto) do
			if nextHeader == name then
				namedArgs[pre .. "IsData"] = type
				break
			end
		end
	end
	return namedArgs
end


----------------------------------------------------------------------------------
---- Packets
----------------------------------------------------------------------------------

--- Cast the packet to a PERCG packet 
pkt.getPercgPacket = packetCreate("eth", "percg") 

-- TODO(lav): cast packet to PERC control packet .. 
-- packetCreate("eth", "percg", "percc") where percc is variable length
-- some number of hostState followed by some number of agg
-- or packetCreate("eth", "percg", "percchs", "percchs", "percca", "percca") 
-- too complicated I think I'm gonna have a fixed size array of each field in percc header
-- so cast packet to PERC control packet is packetCreate("eth", "percg", "percc")
-- and to PERC data packet is packetCreate("eth", "percg", "percd")

------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

ffi.metatype("struct percg_header", percgHeader)

return percg
