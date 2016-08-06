------------------------------------------------------------------------
--- @file percc2.lua
--- @brief PERC (1) control protocol utility.
--- Utility functions for the percc1_header structs 
--- defined in \ref headers.lua . \n
--- Includes:
--- - PERCC1 constants
--- - PERCC1 header utility
--- - Definition of PERCC1 packets
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
---- PERC Control constants (nothing special)
----------------------------------------------------------------------------------

--- PERC Control protocol constants
local percc1 = {}

percc1.NUM_HOPS = 2

-- newLabel and oldLabel field value for Control
percc1.LABEL_UNSAT = 0x1
percc1.LABEL_SAT = 0x0
percc1.LABEL_UNDEF = 0x2

-- isExit field value for Control
percc1.IS_NOT_EXIT = 0x0
percc1.IS_EXIT = 0x1

-- isForward field value for Control
percc1.IS_NOT_FORWARD = 0x0
percc1.IS_FORWARD = 0x1

-- newRate and oldRate field value for Control
-- granularity in KBPS 
percc1.RATE_INFINITE = 20000 --2000000000
percc1.RATE_TEN_GBPS = 8000

-----------------------------------------------------------------------------------
---- PERC Per-Hop array structs 
-----------------------------------------------------------------------------------
local percc1LinkData = {}
percc1LinkData.__index = percc1LinkData
local percc1LinkDataType = ffi.typeof("struct percc1_link_data")

local percc1HostState = {}
percc1HostState.__index = percc1HostState
local percc1HostStateType = ffi.typeof("struct percc1_host_state")

local percc1Agg = {}
percc1Agg.__index = percc1Agg
local percc1AggType = ffi.typeof("struct percc1_agg")


-- Retrieve the values of all members
-- return Values in string format
function percc1LinkData:getString()
   return "[dataQueueSize=" .. tostring(self:getDataQueueSize()) ..
      ", ctrlQueueSize=" .. tostring(self:getControlQueueSize()) ..
      ", linkUtilization=" .. tostring(self:getLinkUtilization()) ..
      ", bos=" .. tostring(self:getBos()) .. "]"
end

function percc1LinkData:getDataQueueSize()
   return self.dataQueueSize
end

function percc1LinkData:getControlQueueSize()
   return self.dataQueueSize
end

function percc1LinkData:getLinkUtilization()
   return self.linkUtilization
end

-- Set the new data queue size (only to initialize)
function percc1LinkData:setNewDataQueueSize(int)
   int = int or 0
    self.dataQueue = (int)
end

-- Set the new control queue size (only to initialize)
function percc1LinkData:setNewControlQueueSize(int)
   int = int or 0
    self.controlQueue = (int)
end

-- Set the new data queue size (only to initialize)
function percc1LinkData:setNewLinkUtilizationSize(int)
   int = int or 0
    self.linkUtilization = (int)
end

-- Set the "bos" field (to 1 if last hop else 0)
function percc1LinkData:setBos(int)
    int = int or 0
    self.bos = int
end


-- Retrieve the values of all members
-- return Values in string format
function percc1HostState:getString()
    return "[newLabel=" .. self:getNewLabelString() ..
    	   ", newRate=" .. tostring(self:getNewRate()) ..
	   ", oldLabel=" .. self:getOldLabelString() ..
	   ", oldRate=" .. tostring(self:getOldRate()) .. 
	   ", bos=" .. tostring(self:getBos()) .. "]"
end

-- Retrieve the new rate
function percc1HostState:getNewRate()
	 return self.newRate
end

-- Retrieve the old rate
function percc1HostState:getOldRate()
	 return (self.oldRate)
end

-- Retrieve the new label
function percc1HostState:getNewLabel()
	 return self.newLabel
end

-- Retrieve the old label
function percc1HostState:getOldLabel()
	 return self.oldLabel
end

--- Retrieve oldLabel. 
--- @return oldLabel as string.
function percc1HostState:getOldLabelString()
	local proto = self:getOldLabel()
	local cleartext = ""
	
	if proto == percc1.LABEL_SAT then
		cleartext = "(SAT)"
	elseif proto == percc1.LABEL_UNSAT then
		cleartext = "(UNSAT)"
	elseif proto == percc1.LABEL_UNDEF then
		cleartext = "(UNDEF)"		
	else
		cleartext = "(unknown)"
	end
	return format("0x%02x %s", proto, cleartext)
end

--- Retrieve newLabel. 
--- @return newLabel as string.
function percc1HostState:getNewLabelString()
	local proto = self:getNewLabel()
	local cleartext = ""
	
	if proto == percc1.LABEL_SAT then
		cleartext = "(SAT)"
	elseif proto == percc1.LABEL_UNSAT then
		cleartext = "(UNSAT)"
	elseif proto == percc1.LABEL_UNDEF then
		cleartext = "(UNDEF)"		
	else
		cleartext = "(unknown)"
	end
	return format("0x%02x %s", proto, cleartext)
end

-- Retrieve the values of all members
-- return Values in string format
function percc1Agg:getString()
    return "[capacity=" .. tostring(self:getLinkCapacity()) ..
    	   ", sumSat=" .. tostring(self:getSumSat()) ..
	   ", numSat=" .. tostring(self:getNumSat()) ..
	   ", numUnsat=" .. tostring(self:getNumUnsat()) .. 
	   ", bos=" .. tostring(self:getBos()) .. "]"
end

-- Retrieve the link capacity 
function percc1Agg:getLinkCapacity()
	 return (self.linkCapacity)
end

-- Retrieve the sum of sat. flows
function percc1Agg:getSumSat()
	 return (self.sumSat)
end

-- Retrieve the num of sat. flows
function percc1Agg:getNumSat()
	 return (self.numSat)
end

-- Retrieve the num of unsat. flows
function percc1Agg:getNumUnsat()
	 return (self.numUnsat)
end

-- Set the new rate
function percc1HostState:setNewRate(int)
   int = int or percc1.RATE_INFINITE
    self.newRate = (int)
end

-- Set the old rate
function percc1HostState:setOldRate(int)
   int = int or percc1.RATE_INFINITE
   self.oldRate = (int)
end

-- Set the new label
function percc1HostState:setNewLabel(int)
    int = int or percc1.LABEL_UNSAT
    self.newLabel = int
end

-- Set the old label
function percc1HostState:setOldLabel(int)
    int = int or percc1.LABEL_UNDEF
    self.oldLabel = int
end

-- Set the link capacity
function percc1Agg:setLinkCapacity(int)
    int = int or percc1.RATE_INFINITE --percc1.RATE_TEN_GBPS
    self.linkCapacity = (int)
end

-- Set the sum of sat. flows
function percc1Agg:setSumSat(int)
    int = int or 0
    self.sumSat = (int)
end

-- Set the num of sat. flows
function percc1Agg:setNumSat(int)
    int = int or 0
    self.numSat = (int)
end

-- Set the num of unsat. flows
function percc1Agg:setNumUnsat(int)   
   int = int or 0
    self.numUnsat = (int)
end

-- Set the "bos" field (to 1 if last hop else 0)
function percc1Agg:setBos(int)
    int = int or 0
    self.bos = int
end

-- Set the "bos" field (to 1 if last hop else 0)
function percc1HostState:setBos(int)
    int = int or 0
    self.bos = int
end

-- Retrieve the "bos" field
function percc1Agg:getBos()
    return self.bos
end

-- Retrieve the "bos" field
function percc1HostState:getBos()
    return self.bos
end

-- Retrieve the "bos" field
function percc1LinkData:getBos()
    return self.bos
end


--- Retrieve the string representation of the rates.
--- @return Address in string format.
--function ip4Addr:getString()
--	return ("%d.%d.%d.%d"):format(self.uint8[0], --self.uint8[1], self.uint8[2], self.uint8[3])
--end


-----------------------------------------------------------------------------------
---- PERC Control header
-----------------------------------------------------------------------------------

--- Module for percc1_header struct (see \ref headers.lua).
local percc1Header = {}

percc1Header.__index = percc1Header

--- Indicate if exit packet.
--- @param int isExit of percc1 header as 8 bit integer.
function percc1Header:setIsExit(int)
	int = int or percc1.IS_NOT_EXIT 
	self.isExit = int
end

--- Indicate if forward packet.
--- @param int isForward of percc1 header as 8 bit integer.
function percc1Header:setIsForward(int)
	int = int or percc1.IS_FORWARD 
	self.isForward = int
end


--- Set the initial hop.
--- @param int hop of percc1 header as 8 bit integer.
--- Should be 1.
function percc1Header:setHop(int)
	int = int or 1 
	self.hop = int
end

--- Increment hop
--- @param increment int hop of percc1 header as 8 bit integer.
function percc1Header:incrementHop()
	self.hop = self.hop + 1
end

--- Decrement hop
--- @param decrement int hop of percc1 header as 8 bit integer.
function percc1Header:decrementHop()
	self.hop = self.hop - 1
end

--- Initialize maximum hops.
--- @param int hop of percc1 header as 8 bit integer.
--- Should be 0.
function percc1Header:setMaxHops(int)
	int = int or 0 
	self.maxHops = int
end

--- Set the bos field of linkData for the ith hop.
function percc1Header:setBosLinkData(hop, int)
	 if hop == 1 then self.linkData:setBos(int)
	 else self.linkData2:setBos(int) end
end

--- Set the dataQueueSize for the ith hop.
--- @param int dataQueueSize[i] of percc1 header as 32 bit integer.
function percc1Header:setDataQueueSize(hop, int)
   if hop == 1 then self.linkData:setDataQueueSize(int)
   else self.linkData2:setDataQueueSize(int) end
end

--- Set the controlQueueSize for the ith hop.
--- @param int controlQueueSize[i] of percc1 header as 32 bit integer.
function percc1Header:setControlQueueSize(hop, int)
   if hop == 1 then self.linkData:setControlQueueSize(int)
   else self.linkData2:setControlQueueSize(int) end
end

--- Set the linkUtilization for the ith hop.
--- @param int linkUtilization[i] of percc1 header as 32 bit integer.
function percc1Header:setLinkUtilization(hop, int)
   if hop == 1 then self.linkData:setLinkUtilization(int)
   else self.linkData2:setLinkUtilization(int) end
end

--- Set the bos field of hostState for the ith hop.
function percc1Header:setBosHostState(hop, int)
	 if hop == 1 then self.hostState:setBos(int)
	 else self.hostState2:setBos(int) end
end

--- Set the bos field of agg for the ith hop.
function percc1Header:setBosAgg(hop, int)
	 if hop == 1 then self.agg:setBos(int)
	 else self.agg2:setBos(int) end
end

--- Set the newRate for the ith hop.
--- @param int newRate[i] of percc1 header as 32 bit integer.
function percc1Header:setNewRate(hop, int)
   if hop == 1 then self.hostState:setNewRate(int)
   else self.hostState2:setNewRate(int) end
end

--- Set the oldRate for the ith hop.
--- @param int oldRate[i] of percc1 header as 32 bit integer.
function percc1Header:setOldRate(hop, int)
	 if hop == 1 then self.hostState:setOldRate(int)
	 else self.hostState2:setOldRate(int) end
end

--- Set the newLabel for the ith hop.
--- @param int newLabel[i] of percc1 header as 32 bit integer.
function percc1Header:setNewLabel(hop, int)
	 if hop == 1 then self.hostState:setNewLabel(int)
	 else self.hostState2:setNewLabel(int) end
end

--- Set the oldLabel for the ith hop.
--- @param int oldLabel[i] of percc1 header as 32 bit integer.
function percc1Header:setOldLabel(hop, int)
	 if hop == 1 then self.hostState:setOldLabel(int)
	 else self.hostState2:setOldLabel(int) end
end

--- Set the linkCapacity for the ith hop.
--- @param int linkCapacity[i] of percc1 header as 32 bit integer.
function percc1Header:setLinkCapacity(hop, int)
	 if hop == 1 then self.agg:setLinkCapacity(int)
	 else self.agg2:setLinkCapacity(int) end
end

--- Set the sumSat for the ith hop.
--- @param int sumSat[i] of percc1 header as 32 bit integer.
function percc1Header:setSumSat(hop, int)
	 if hop == 1 then self.agg:setSumSat(int)
	 else self.agg2:setSumSat(int) end
end

--- Set the numSat for the ith hop.
--- @param int numSat[i] of percc1 header as 32 bit integer.
function percc1Header:setNumSat(hop, int)
	 if hop == 1 then self.agg:setNumSat(int)
	 else self.agg2:setNumSat(int) end
end

--- Set the numUnsat for the ith hop.
--- @param int numUnsat[i] of percc1 header as 32 bit integer.
function percc1Header:setNumUnsat(hop, int)
   if hop == 1 then self.agg:setNumUnsat(int)
   else self.agg2:setNumUnsat(int) end
end

--- Check if exit packet. 
--- @return int isExit as 8 bit integer.
function percc1Header:getIsExit()
	return self.isExit
end

--- Check if forward packet
--- @return int isForward as 8 bit integer.
function percc1Header:getIsForward()
	return self.isForward
end

--- Retrieve isForward. 
--- @return isForward as string.
function percc1Header:getIsForwardString()
	local proto = self:getIsForward()
	local cleartext = ""
	
	if proto == percc1.IS_FORWARD then
		cleartext = "(FORWARD)"
	elseif proto == percc1.IS_NOT_FORWARD then
		cleartext = "(NOT_FORWARD)"
	else
		cleartext = "(unknown)"
	end

	return format("0x%02x %s", proto, cleartext)
end


--- Retrieve isExit. 
--- @return isExit as string.
function percc1Header:getIsExitString()
	local proto = self:getIsExit()
	local cleartext = ""
	
	if proto == percc1.IS_EXIT then
		cleartext = "(EXIT)"
	elseif proto == percc1.IS_NOT_EXIT then
		cleartext = "(NOT_EXIT)"
	else
		cleartext = "(unknown)"
	end

	return format("0x%02x %s", proto, cleartext)
end


--- Retrieve the hop field. 
--- @return Hop as 8 bit integer.
function percc1Header:getHop()
	return self.hop
end

--- Retrieve the maximum hops. 
--- @return MaxHops as 8 bit integer.
function percc1Header:getMaxHops()
	return self.maxHops
end

function percc1Header:getBottleneckInfo(maxHops)
         local bnInfo = {}
	 local bnRate1 = percc1.RATE_INFINITE
	 local bnRate2 = percc1.RATE_INFINITE
	 local bnBitmap = {}
	 local rates = {}

	 for i=1,maxHops do
	     local numUnsat = self:getNumUnsat(i)
	     if numUnsat > 0 then
	     	local rate = self:getLinkCapacity(i)/numUnsat
		rates[i] = rate
		if rate < bnRate1 then
		   bnRate2 = bnRate1
		   bnRate1 = rate
		   else if rate < bnRate2 then
		   	bnRate2 = rate
		    	end
		end
	     end
	 end

	 for i=1,maxHops do
	     if rates[i] ~= nil and rates[i] <= bnRate1 then
	     	bnBitmap[i] = 1
		end
	 end

	 bnInfo["bnRate1"] = bnRate1
	 bnInfo["bnRate2"] = bnRate2
	 bnInfo["bnBitmap"] = bnBitmap
	 
	 return bnInfo
end

--- Retrieve the dataQueueSize for the ith hop. 
--- @return dataQueueSize[i] as 32 bit integer.
function percc1Header:getDataQueueSize(hop)
	 if hop == 1 then return self.linkData:getDataQueueSize()
	 else return self.linkData2:getDataQueueSize() end

end

--- Retrieve the controlQueueSize for the ith hop. 
--- @return controlQueueSize[i] as 32 bit integer.
function percc1Header:getControlQueueSize(hop)
	 if hop == 1 then return self.linkData:getControlQueueSize()
	 else return self.linkData2:getControlQueueSize() end

end

--- Retrieve the linkUtilization for the ith hop. 
--- @return linkUtilization[i] as 32 bit integer.
function percc1Header:getLinkUtilization(hop)
	 if hop == 1 then return self.linkData:getLinkUtilization()
	 else return self.linkData2:getLinkUtilization() end

end

--- Retrieve the newRate for the ith hop. 
--- @return newRate[i] as 32 bit integer.
function percc1Header:getNewRate(hop)
	 if hop == 1 then return self.hostState:getNewRate()
	 else return self.hostState2:getNewRate() end

end

--- Retrieve the oldRate for the ith hop. 
--- @return oldRate[i] as 32 bit integer.
function percc1Header:getOldRate(hop)
	 if hop == 1 then return self.hostState:getOldRate()
	 else return self.hostState2:getOldRate() end
end

--- Retrieve the newLabel for the ith hop. 
--- @return newLabel[i] as 32 bit integer.
function percc1Header:getNewLabel(hop)
	 if hop == 1 then return self.hostState:getNewLabel()
	 else return self.hostState2:getNewLabel() end
end

--- Retrieve the newLabel for the ith hop as String. 
--- @return newLabel[i] as String.
function percc1Header:getNewLabelString(hop)
	 if hop == 1 then return self.hostState:getNewLabelString()
	 else return self.hostState2:getNewLabelString() end

end

--- Retrieve the oldLabel for the ith hop. 
--- @return oldLabel[i] as 32 bit integer.
function percc1Header:getOldLabel(hop)
	 if hop == 1 then return self.hostState:getOldLabel()
	 else return self.hostState2:getOldLabel() end
end

--- Retrieve the oldLabel for the ith hop as String. 
--- @return oldLabel[i] as String.
function percc1Header:getOldLabelString(hop)
	if hop == 1 then return self.hostState:getOldLabelString()
	else return self.hostState2:getOldLabelString() end
end

--- Retrieve the linkCapacity for the ith hop. 
--- @return linkCapacity[i] as 32 bit integer.
function percc1Header:getLinkCapacity(hop)
	if hop == 1 then return self.agg:getLinkCapacity()
	else return self.agg2:getLinkCapacity() end
end

--- Retrieve the sumSat for the ith hop. 
--- @return sumSat[i] as 32 bit integer.
function percc1Header:getSumSat(hop)
	if hop == 1 then return self.agg:getSumSat()
	else return self.agg2:getSumSat() end
end

--- Retrieve the numSat for the ith hop. 
--- @return numSat[i] as 32 bit integer.
function percc1Header:getNumSat(hop)
	if hop == 1 then return self.agg:getNumSat()
	else return self.agg2:getNumSat() end
end

--- Retrieve the numUnsat for the ith hop. 
--- @return numUnsat[i] as 32 bit integer.
function percc1Header:getNumUnsat(hop)
	if hop == 1 then return self.agg:getNumUnsat()
	else return self.agg2:getNumUnsat() end
end

--- Set all members of the percc1 header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: IsExit, IsForward, Hop, MaxHops, NewRateX, NewLabelX, OldRateX, OldLabelX, LinkCapacityX, SumSatX, NumSatX, NumUnsatX. X is the hop number.
--- @param pre prefix for namedArgs. Default 'percc1'.
--- @code
--- fill() --- only default values
--- fill{ percc1IsExit=percc1.IS_EXIT, percc1Hop=1 } --- all members are set to default values with the exception of percc1IsExit and percc1Hop
--- @endcode
function percc1Header:fill(args, pre)
	args = args or {}
	pre = pre or "percc1"

	self:setIsExit(args[pre .. "IsExit"])
	self:setIsForward(args[pre .. "IsForward"])
	self:setHop(args[pre .. "Hop"])
	self:setMaxHops(args[pre .. "MaxHops"])

	for i=1,percc1.NUM_HOPS do
	   self:setDataQueueSize(i, args[pre .. "DataQueueSize" .. i])
	   self:setControlQueueSize(i, args[pre .. "ControlQueueSize" .. i])
	   self:setLinkUtilization(i, args[pre .. "LinkUtilization" .. i])
	   self:setNewRate(i, args[pre .. "NewRate" .. i])	  
	   self:setOldRate(i, args[pre .. "OldRate" .. i])
	   assert(self:getOldRate(i) == percc1.RATE_INFINITE)
	   self:setNewLabel(i, args[pre .. "NewLabel" .. i])
	   self:setOldLabel(i, args[pre .. "OldLabel" .. i])
	   self:setLinkCapacity(i, args[pre .. "LinkCapacity" .. i])
	   assert(self:getLinkCapacity(i) == percc1.RATE_INFINITE)
	   self:setSumSat(i, args[pre .. "SumSat" .. i])
	   self:setNumSat(i, args[pre .. "NumSat" .. i])
	   self:setNumUnsat(i, args[pre .. "NumUnsat" .. i])
	end
	
	self.agg:setBos(0)
	self.hostState:setBos(0)
	self.linkData:setBos(0)

	self.agg2:setBos(1)
	self.hostState2:setBos(1)
	self.linkData2:setBos(1)
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'percc1'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see percc1Header:fill
function percc1Header:get(pre)
	pre = pre or "percc1"

	local args = {}
	args[pre .. "IsExit"] = self:getIsExit()
	args[pre .. "IsForward"] = self:getIsForward()
	args[pre .. "Hop"] = self:getHop()
	args[pre .. "MaxHops"] = self:getMaxHops()
	
	for i=1,percc1.NUM_HOPS do
	   args[pre .. "DataQueueSize" .. i] = self:getDataQueueSize(i)
	   args[pre .. "ControlQueueSize" .. i] = self:getControlQueueSize(i)
	   args[pre .. "LinkUtilization" .. i] = self:getLinkUtilization(i)
	   args[pre .. "NewRate" .. i] = self:getNewRate(i)
	   args[pre .. "NewLabel" .. i] = self:getNewLabel(i)
	   args[pre .. "OldRate" .. i] = self:getOldRate(i)
	   args[pre .. "OldLabel" .. i] = self:getOldLabel(i)
	   args[pre .. "LinkCapacity" .. i] = self:getLinkCapacity(i)
	   args[pre .. "SumSat" .. i] = self:getSumSat(i)
	   args[pre .. "NumSat" .. i] = self:getNumSat(i)
	   args[pre .. "NumUnsat" .. i] = self:getNumUnsat(i)
	end
	return args	
end

function percc1Header:doHton()
 -- changes linkCapacity, sumSat in agg
 -- changes oldRate, newRate in hostState
   for i=1,percc1.NUM_HOPS do
      local dataQueueSize = self:getDataQueueSize(i)
      local controlQueueSize = self:getControlQueueSize(i)
      local linkUtilization = self:getLinkUtilization(i)
      
      local linkCapacity = self:getLinkCapacity(i)
      local sumSat = self:getSumSat(i)
      local numSat = self:getNumSat(i)
      local numUnsat = self:getNumUnsat(i)

      local oldRate = self:getOldRate(i)
      local newRate = self:getNewRate(i)

      self:setDataQueueSize(i, hton(dataQueueSize))
      self:setControlQueueSize(i, hton(controlQueueSize))
      self:setLinkUtilization(i, hton(linkUtilization))
      
     self:setLinkCapacity(i, hton(linkCapacity))
     self:setSumSat(i, hton(sumSat))
     self:setNumSat(i, hton(numSat))
     self:setNumUnsat(i, hton(numUnsat))

     self:setOldRate(i, hton(oldRate))
     self:setNewRate(i, hton(newRate))
 end
end

function percc1Header:doNtoh()
 -- changes linkCapacity, sumSat in agg
 -- changes oldRate, newRate in hostState
 for i=1,percc1.NUM_HOPS do
      local dataQueueSize = self:getDataQueueSize(i)
      local controlQueueSize = self:getControlQueueSize(i)
      local linkUtilization = self:getLinkUtilization(i)
      
    local linkCapacity = self:getLinkCapacity(i)
     local sumSat = self:getSumSat(i)
     local numSat = self:getNumSat(i)
     local numUnsat = self:getNumUnsat(i)

     local oldRate = self:getOldRate(i)
     local newRate = self:getNewRate(i)

     self:setDataQueueSize(i, ntoh(dataQueueSize))
      self:setControlQueueSize(i, ntoh(controlQueueSize))
      self:setLinkUtilization(i, ntoh(linkUtilization))

     self:setLinkCapacity(i, ntoh(linkCapacity))
     self:setSumSat(i, ntoh(sumSat))
     self:setNumSat(i, ntoh(numSat))
     self:setNumUnsat(i, ntoh(numUnsat))

     self:setOldRate(i, ntoh(oldRate))
     self:setNewRate(i, ntoh(newRate))
 end
end

--- TODO(lav): fill out maybe show per hop, preferable for filled out
---  hops only, maybe a valid field per hop?
--- Retrieve the values of all members.
--- @return Values in string format.
function percc1Header:getString()
	return "PERCC1 " .. self:getIsForwardString() ..
	" " .. self:getIsExitString() ..
	" hop " .. self:getHop() ..
	   " maxHops " .. self:getMaxHops() ..
	   "\n Hop 1 " .. self.hostState:getString() ..
	   " Hop 2 " .. self.hostState2:getString() ..
	   ".\n Hop 1 " .. self.agg:getString() ..
	   " Hop 2 " .. self.agg2:getString()
	"\n Hop 1 " .. self.linkData:getString() ..
	   " Hop 2 " .. self.linkData2:getString() ..	   


--" Hop 3 " .. self.hostState[3]:getString() ..
--" Hop 4 " .. self.hostState[4]:getString() ..
--" Hop 3 " .. self.agg[3]:getString() ..
--" Hop 4 " .. self.agg[4]:getString() .. ".\n"

end


--- Resolve which header comes after this one (in a packet).
--- For instance: in tcp/udp based on the ports.
--- This function must exist and is only used when get/dump is executed on
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'udp', 'icmp', nil)
function percc1Header:resolveNextHeader()
	return nil
end

--- TODO(lav): I think this doesn't matter.
--- Change the default values for namedArguments (for fill/get).
--- This can be used to for instance calculate a length value based on the total packet length.
--- See proto/ip4.setDefaultNamedArgs as an example.
--- This function must exist and is only used by packet.fill.
--- @param pre The prefix used for the namedArgs, e.g. 'percc1'
--- @param namedArgs Table of named arguments (see See Also)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see percc1Header:fill
function percc1Header:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	-- TODO(lav): not sure if this is relevant to PERCC1
	-- set length
	if not namedArgs[pre .. "Length"] and namedArgs["pktLength"] then
		namedArgs[pre .. "Length"] = namedArgs["pktLength"] - accumulatedLength
	end

	return namedArgs
end


----------------------------------------------------------------------------------
---- Packets
----------------------------------------------------------------------------------

--- Cast the packet to a PERCC1 packet 
pkt.getPercc1Packet = packetCreate("eth", "percg", "percc1") 

------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

ffi.metatype("struct percc1_link_data", percc1LinkData)
ffi.metatype("struct percc1_host_state", percc1HostState)
ffi.metatype("struct percc1_agg", percc1Agg)
ffi.metatype("struct percc1_header", percc1Header)


return percc1
