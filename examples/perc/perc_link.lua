local ffi = require("ffi")
local pkt = require("packet")

local dpdk		= require "dpdk"
local device	= require "device"
local log 		= require "log"
local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"
local pcap = require "pcap"

local Link = {sumSat = 0, numSat = 0, numUnsat = 0, linkCapacity = percc1.RATE_TEN_GBPS}

function Link:new (o)
  o = o or {}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Link:processPercc1Packet (pkt)
    --local pkt = buf:getPercc1Packet()

    if (pkt.percc1:getIsForward() == percc1.IS_NOT_FORWARD) then
       -- reverse packets use hop-1 to index into right agg/ hostState       
       pkt.percc1:decrementHop()
    end
    -- forward packets use hop to index into right agg/ hostState
    
    local hop = pkt.percc1:getHop()+1 -- lua index starts with 1
    if (hop ~= 1 and hop ~= pkt.percc1:getMaxHops())
       then print("Hop is neither 1 nor maxHops!! WRONG")
    end
    local oldLabel = pkt.percc1:getOldLabel(hop)
    local newLabel = pkt.percc1:getNewLabel(hop)			  

    if pkt.percc1:getIsExit() == percc1.IS_EXIT and pkt.percc1:getIsForward() == percc1.IS_NOT_FORWARD
    then 
      if oldLabel == percc1.LABEL_UNSAT then self.numUnsat = self.numUnsat - 1 
           elseif oldLabel == percc1.LABEL_SAT then 
      	   	self.numSat = self.numSat - 1
	   	self.sumSat = self.sumSat - pkt.percc1:getOldRate(hop)
      end
      else
	   if oldLabel == percc1.LABEL_UNDEF and newLabel == percc1.LABEL_UNSAT then
	      	 self.numUnsat = self.numUnsat + 1	      
	      elseif oldLabel == percc1.LABEL_UNSAT and newLabel == percc1.LABEL_SAT then
	        self.numUnsat = self.numUnsat - 1
	        self.numSat = self.numSat + 1
	        self.sumSat = self.sumSat + pkt.percc1:getNewRate(hop)
	      elseif oldLabel == percc1.LABEL_SAT and newLabel == percc1.LABEL_UNSAT then
	        self.numUnsat = self.numUnsat + 1
	        self.numSat = self.numSat -1
	        self.sumSat = self.sumSat - pkt.percc1:getOldRate(hop)
	      elseif oldLabel == percc1.LABEL_SAT and newLabel == percc1.LABEL_SAT then
	        if pkt.percc1:getNewRate(hop) ~= pkt.percc1:getOldRate(hop) then
		   self.sumSat = self.sumSat + pkt.percc1:getNewRate(hop) - pkt.percc1:getOldRate(hop)
                end
	      elseif oldLabel == percc1.LABEL_UNSAT and newLabel == percc1.LABEL_UNSAT then
	        self.sumSat = self.sumSat
              else
		print("unexpected labels oldLabel is " .. pkt.percc1:getOldLabelString(hop)
		.. " and newLabel is " .. pkt.percc1:getNewLabelString(hop) ..  ".\n")
	   end
     end

     pkt.percc1:setLinkCapacity(hop, self.linkCapacity)
     pkt.percc1:setSumSat(hop, self.sumSat)
     pkt.percc1:setNumUnsat(hop, self.numUnsat)
     pkt.percc1:setNumSat(hop, self.numSat)
     --print("At link, incrementing hop from " .. hop .. " to " .. hop+1) 

     --print(" packet looks like " .. pkt.percc1:getString())

     if (pkt.percc1:getIsForward() == percc1.IS_FORWARD) then
        pkt.percc1:incrementHop()
	end

end

return Link