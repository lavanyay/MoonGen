local ffi = require("ffi")
local pkt = require("packet")

local dpdk	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local pipe		= require "pipe"
local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"
local pcap = require "pcap"

local ipc = require "examples.perc.ipc"

local Link = require "examples.perc.perc_link"

local EndHost = {
	rates = {},
	queueRates = {}, -- queue x : current, next, changeTime
	freeQueues = {},
	queues = {},
	numPendingMsgs = 0,
	pendingMsgs = {},
	pendingChangeRate = {},
	pendingFin = {},
	egressLink = Link:new(),
	id = nil,
	pipes = nil,
	rx = nil,
	txBufs = nil,
	rxBufs = nil,
	rxQueue = nil,
	txQueue = nil,
	PKT_SIZE = nil,
	dev = nil,
}

EndHost.__index = EndHost

function EndHost.new (mem, dev, id, pipes, PKT_SIZE)
   local self = setmetatable({}, EndHost)
   self.id = tonumber(id)
  self.txHexdumpFile = io.open("control-".. id .. "-txhexdump.txt", "a")
  self.logFile = io.open("control-".. id .. "-log.txt", "a")
  self.rateFile = io.open("control-".. id .. "-rates.txt", "a")
  self.txBufs = mem:bufArray(32)
  self.rxBufs = mem:bufArray(32)
  self.rx = 0
  self.txQueue = dev:getTxQueue(0)
  self.rxQueue = dev:getRxQueue(0)
  self.PKT_SIZE = PKT_SIZE
  self.dev = dev
  self.pipes = pipes
  
  	-- initialize available tx queues for data slave to use
	-- queue 0 is used for control packets
  for i=0, 127 do
    if (127-i) ~= 0 then 
      table.insert(self.freeQueues, 127-i)
    end
  end

  return self
end

function EndHost:resetPendingMsgs() 
  self.numPendingMsgs = 0
  self.pendingMsgs = {}
  self.pendingChangeRate = {}
end


function EndHost:tryRecv()
	 local rx = endHost.rxQueue:tryRecv(self.rxBufs, 20)
	 self.rx = rx
	 return rx
end

function EndHost:sendPendingMsgs(now)
   self.txBufs:allocN(self.PKT_SIZE, self.numPendingMsgs)
   local bufNo = 1

   for flowId, info in pairs(self.pendingMsgs) do
      local rawPkt = self.txBufs[bufNo]
      local pkt = self.txBufs[bufNo]:getPercc1Packet()
      -- either new flow or received flow # matches ..
      assert(info.rxFlowNo == nil or flowId == info.rxFlowNo)
      if true then
	 -- update perc generic header
	 self:updatePercGeneric(pkt, flowId, info, now)	 
	 -- update percc1 control header fields
	 self:updatePercControl(pkt, flowId, info, now)
		   
	 -- egress processing for forward packets
	 if pkt.percc1:getIsForward() == percc1.IS_FORWARD then 
	    --self.egressLink:processPercc1Packet(pkt)
	 end		   

	 local timeDiff = 0
	 if (info.rxTime ~= nil and now ~= nil) then
	    timeDiff = (now - info.rxTime)*1e6
	 end

	 -- stats of time between read new flow updates from app and start of tx
	 -- grep SEND control-1-log.txt | grep "maxHops 0" | cut -d' ' -f3 | Rscript -e 'summary (as.numeric (readLines ("stdin")))'

	 -- stats of time between start of rx and start of tx
	 -- grep SEND control-1-log.txt | cut -d' ' -f3 | Rscript -e 'summary (as.numeric (readLines ("stdin")))'

	 -- TODO(lav): find out
	 -- hmm.. what causes max 500us etc. gaps?
	 -- what's typical gap between application sends new flow update
	 -- and start of tx
	 self.logFile:write("SEND [ " .. timeDiff .. " us]"
			       .. pkt.percg:getString()
			       .. " " .. pkt.percc1:getString() .. "\n")

		      -- prints packet and dumps bytes to stdout (colorized)
		      -- commented out, cuz maybe you don't want to see
		      -- continous stream of packets sent in console
		      -- rawPkt:dump(self.PKT_SIZE, io.stdout, true)
		      
		      -- prints packet and
		      -- dumps bytes to log-file (not colorized)
		      rawPkt:dump(self.PKT_SIZE, self.txHexdumpFile, false)
		      -- see note about Ntoh
		      pkt.percc1:doHton()
		      bufNo = bufNo + 1
	       	  end

	       end -- ends for flow, info in pairs(pendingMsgs)..

   self.txQueue:send(self.txBufs)	   
end

function EndHost:changeRates()
   -- update next rate, changeTime for all queues
   -- cases:
   -- no current rate
   -- or if new rate is smaller, simply update next rate, changeTime now
   -- if new rate is bigger, see if there's a next rate scheduled
   -- if no next rate or if next rate is smaller, update next rate, reset changeTime
   -- or if next rate is bigger, update nextRate but don't changeTime   
   
   local now = dpdk.getTime()
   for flowNo, rate in pairs(self.pendingChangeRate) do
      local queueNo = self.queues[flowNo]
      if queueNo ~= nil then
	 --print("Found queue " .. queueNo .. " for flow " .. flowNo)
	 local rates = self.queueRates[queueNo]
	 if rates == nil or rates.current < rate then
	    rates = {}
	    rates["flowNo"] = flowNo
	    rates["current"] = nil
	    rates["next"] = rate
	    rates["changeTime"] = now
	 elseif rates.next == nil or rates.next < rate then
	    rates["next"] = rate
	    rates["changeTime"] = now + 2
	 else
	    rates["next"] = rate
	 end
	 self.queueRates[queueNo] = rates
      else
	 --print("No queue assigned for flow " .. flowNo)
      end
   end
   self:updateRates(now)
end

function EndHost:updateRates(now)
   for queueNo, rates in pairs(self.queueRates) do
      if rates.changeTime ~= nil and rates.changeTime <= now then
	 rates["current"] = rates["next"]
	 rates["next"] = nil
	 rates["changeTime"] = nil
	 ipc.sendMsgs(self.pipes, "slowPipeControlToApp",
		      {["msg"]= ("updated rate of flow " 
				    .. rates["flowNo"] .. " to "
				    .. rates["current"]), ["now"]= now})
	 if (true) then self.dev:getTxQueue(queueNo):setRate(rates["current"]) end
      end
   end   
end

-- pendingFin, queues, freeQueues
function EndHost:handleFlowCompletions(msgs) 
   for msgNo, msg in pairs(msgs) do
      local flowId = tonumber(msg.flow)
      -- do it asap to free bandwidth
      self.pendingFin[flowId] = true
      --print("Adding flow " .. msg.flow .. " to pending fin")
      -- reclaim queue
      local queueNo = self.queues[flowId]
      assert(queueNo ~= nil)
      if queueNo ~= nil then
	 self.queueRates[queueNo] = nil
	 table.insert(self.freeQueues, queueNo)
	 self.queues[flowId] =  nil
      end -- ends if self.queues
   end -- ends for msgNo,..	      	   
end

-- pendingMsgs, freeQueues, queues,
function EndHost:handleNewFlows(msgs, now)
   --print("handle new flows")
   for msgNo, msg in pairs(msgs) do
      local flowId = msg.flow
      if next(self.freeQueues) ~= nil then
	 assert(self.queues[flowId] == nil)
	 assert(self.pendingMsgs[flowId] == nil)
	
	 -- log pending message
	 self.pendingMsgs[flowId] = {["other"]=msg.destination,
	    ["rxTime"]=now}
	 
	 self.numPendingMsgs = self.numPendingMsgs + 1
	 -- assign queue
	 local queue = table.remove(self.freeQueues)
	 self.queues[flowId] = queue
	 --print("Assigned queue " .. queue .. " to " .. flowId)
	 -- tell data slave to start sending       
	 local startDataMsg = msg
	 ipc.sendFcdStartMsg(self.pipes, msg.flow, msg.destination, queue)
	 --msg["queue"]=queue
	 --ipc.sendMsgs(self.pipes, "fastPipeControlToDataStart", msg)
      end -- ends if next(freeQueues..
   end -- ends for msgNo..
end

function EndHost:handleRxUpdates(now)
   for i = 1, self.rx do
      local buf = self.rxBufs[i]

      local pkt = buf:getPercc1Packet()
      -- TODO(lav): I'd use ntoh just after rxing packet form network 
      -- and hton just before sending. Network byte is big endian
      -- and mules are little endian. But working fine without both..
      pkt.percc1:doNtoh()

      self.logFile:write("RECEIVE " .. pkt.percg:getString() .. " " .. pkt.percc1:getString() .. "\n")

      local flowId = pkt.percg:getFlowId()
      if flowId == 0 then error("Unexpected flow id 0") end

      assert(self.pendingMsgs[flowId] == nil)
      --print("we already have a pending msg for " .. flowId .. " ignore.")
      --end

      if self.pendingMsgs[flowId] == nil then	 
	 assert(pkt.percg:getDestination() == self.id)
	 local other = pkt.percg:getSource()
	 
	 --if pkt.percc1:getIsForward() == percc1.IS_NOT_FORWARD then
	 --   other = pkt.percc1:getDestination()
	 --end	 	 
	 -- index into the received packet, to use for the
	 -- next packet we send out (esp. for oldLabel, oldRate)
	 self.pendingMsgs[flowId] = {
	    ["rxTime"] = now,
	    ["rxBufNo"] = i,
	    ["rxFlowNo"] = flowId,
	    ["rxNewLabel"] = pkt.percc1:getNewLabel(1),
	    ["rxNewRate"] = pkt.percc1:getNewRate(1),
	    ["rxNewLabel2"] = pkt.percc1:getNewLabel(2),
	    ["rxNewRate2"] = pkt.percc1:getNewRate(2),
	    ["rxIsForward"] = pkt.percc1:getIsForward(),
	    ["rxIsExit"] = pkt.percc1:getIsExit(),
	    ["rxMaxHops"] = pkt.percc1:getMaxHops(),
	    ["rxHop"] = pkt.percc1:getHop(),
	    ["other"] = other
	 }	 	    
	 
	 self.numPendingMsgs = self.numPendingMsgs + 1

	 -- ingress processing for reverse packets
	 if pkt.percc1:getIsForward() == percc1.IS_NOT_FORWARD then 
	    --self.egressLink:processPercc1Packet(pkt)
	 end
	 
	 -- this is how the control packets for a flow finish
	 -- source send exit packet, destination replies with exit packet, end of flow.
	 if pkt.percc1:getIsExit() == percc1.IS_EXIT
	 and pkt.percc1:getIsForward() == percc1.IS_NOT_FORWARD then
	    -- SOURCE GETS FIN-ACK
	    ipc.sendMsgs(self.pipes, "slowPipeControlToApp",
			 {["msg"] = ("control end flow " .. flowId),
			    ["now"] = now})
	    
	    self.pendingMsgs[flowId] = nil
	    self.numPendingMsgs = self.numPendingMsgs - 1
	 end

	 if self.pendingMsgs[flowId] ~= nil then
	    -- the first maxHops entries in the agg and hostState
	    -- arrays that were updated by intermediate hops

	    local maxHops = 0
	    -- for forward packets, intermediate hops increment hop field
	    if pkt.percc1:getIsForward() == percc1.IS_FORWARD then
	       maxHops = pkt.percc1:getHop()
	    else
	       -- for reverse packets, intermediate hops decrement hop field
	       -- but destination puts in the right value in maxHops field
	       maxHops = pkt.percc1:getMaxHops()
	    end

	    -- calculate smallest and second smallest fair share rate
	    -- and list of bottleneck links, to be used to fill in the
	    -- next control packet we send out
	    self.pendingMsgs[flowId]["bnInfo"] = pkt.percc1:getBottleneckInfo(maxHops)
	    if pkt.percc1:getIsForward() == percc1.IS_NOT_FORWARD then
	       local bnRate = self.pendingMsgs[flowId]["bnInfo"].bnRate1
	       if self.rates[flowId] == nil then
		  self.rates[flowId] = bnRate
		  self.pendingChangeRate[flowId] = bnRate
		  --print("Added " .. flowId .. ": " .. bnRate .. " to pending change rates")
		  self.rateFile:write(flowId .. "," .. bnRate .. "\n")
		  --print("Flow " .. flowId .. " started with rate " .. bnRate .. " " .. pkt.percc1:getIsForwardString() .. " " .. pkt.percc1:getIsExitString())
	       elseif bnRate ~= self.rates[flowId] then
		  self.rates[flowId] = bnRate
		  --print("Added " .. flowId .. ": " .. bnRate .. " to pending change rates")
		  self.pendingChangeRate[flowId] = bnRate
		  self.rateFile:write(flowId .. "," .. bnRate .. "\n")
		  --print("Flow " .. flowId .. " changed rate to " .. bnRate .. " " .. pkt.percc1:getIsForwardString() .. " " .. pkt.percc1:getIsExitString())
	       end
	    end			  
	 end -- ends if pendingMsgs ~= nil
      end -- ends if pendingMsgs ~= nil
   end -- ends for i=1,rx

   if self.rx > 0 then  
      self.rxBufs:free(self.rx) 
      self.rx = 0
   end
end

function EndHost:updatePercControl(pkt, flowId, info, now)
   --if info.rxIsForward == percc1.IS_FORWARD then 
   --   print(now .. ": update ctrl pkt for " .. flowId ..  " at destination \n")
   --else
   --   print(now .. ": update ctrl pkt for " .. flowId ..  " at source \n")
   --end
   
	 local rxBufs = self.rxBufs
	 pkt.percc1:setBosAgg(percc1.NUM_HOPS, 1)
	 pkt.percc1:setBosHostState(percc1.NUM_HOPS, 1)

	 if info.rxFlowNo ~= nil and info.bnInfo ~= nil then
	    local bnRate1 = info.bnInfo.bnRate1
	    local bnRate2 = info.bnInfo.bnRate2
	    local bnBitmap = info.bnInfo.bnBitmap
	    local rxNewLabel = info.rxNewLabel
	    local rxNewRate = info.rxNewRate
	    local rxNewLabel2 = info.rxNewLabel2
	    local rxNewRate2 = info.rxNewRate2
	    local rxIsForward = info.rxIsForward
	    local rxIsExit = info.rxIsExit
	    local rxMaxHops = info.rxMaxHops
	    local rxHop = info.rxHop


	    -- Forward packets, hop field is incremented every hop
	    -- starting from 1, so use that for maximum hops.

	    -- TODO(lav): this hops and maxHops stuff looks very
	    -- confusing, but is correct.. I hope
	    local maxHops = 0 
	    if (rxIsForward == percc1.IS_NOT_FORWARD) then
	       -- at source, use hop on received packet would be 1
	       -- so use explicit value of maxHops set by destination
	       -- set starting hop to 0 
	       maxHops = rxMaxHops --rxPkt.percc1:getMaxHops()
	       pkt.percc1:setHop(0)
	       
	       else
	       -- at destination, use hop on received packet to find maxHops
	       -- set starting hop to echo hop on received packet
	       	  maxHops = rxHop --rxPkt.percc1:getHop() 
	       	  pkt.percc1:setHop(rxHop) -- rxPkt.percc1:getHop())
		  
	    end
	    pkt.percc1:setMaxHops(maxHops)
		      
	    -- by default new label is UNDEF and new rate is INFINITE
	    -- and old label is UNDEF and old rate is INFINITE
	    -- set only if different

	    -- FIRST HOP 
	       pkt.percc1:setOldRate(1, rxNewRate)
	       pkt.percc1:setOldLabel(1, rxNewLabel)

	       if bnBitmap[1] then
	          pkt.percc1:setNewRate(1, bnRate2)
		  pkt.percc1:setNewLabel(1, percc1.LABEL_UNSAT)
		  else
		     pkt.percc1:setNewRate(1, bnRate1)
		     pkt.percc1:setNewLabel(1, percc1.LABEL_SAT)
	       end --ends if bnBitmap[j]..  

	       -- SECOND HOP
	       if maxHops == 2 then
	       	  pkt.percc1:setOldRate(2, rxNewRate2)
	       	  pkt.percc1:setOldLabel(2, rxNewLabel2)

	       	  if bnBitmap[2] then
	             pkt.percc1:setNewRate(2, bnRate2)
		     pkt.percc1:setNewLabel(2, percc1.LABEL_UNSAT)
		     else
			pkt.percc1:setNewRate(2, bnRate1)
		     	pkt.percc1:setNewLabel(2, percc1.LABEL_SAT)
	          end --ends if bnBitmap[j]..  
	       end
		             
	     else 
	        -- set rate and label fields for first packet
		pkt.percc1:setMaxHops(0)
		pkt.percc1:setHop(0)
		for j=1,percc1.NUM_HOPS do
		   pkt.percc1:setNewLabel(j, percc1.LABEL_UNSAT)
		   pkt.percc1:setNewRate(j, percc1.INFINITE_RATE)
		   -- newRate and oldRate are default INFINITE
		   pkt.percc1:setOldLabel(j, percc1.LABEL_UNDEF)
		   pkt.percc1:setOldRate(j, percc1.INFINITE_RATE)
		   -- pkt.percc1:setNewRate(j, j)
		end -- ends for j=1,percc1.NUM_HOPS		
	 end -- ends if info.rxBufNo ~= nil
end

function EndHost:updatePercGeneric(pkt, flowId, info, now)
   -- update flowId, source, destination, exit, forward
 local pendingFin = self.pendingFin
 pkt.percg:setFlowId(flowId)
 pkt.percg:setSource(tonumber(self.id))
 pkt.percg:setDestination(tonumber(info.other))

 local pendingFinAck = false

 -- packet to be sent out is reverse packet?
 -- correct for new packets too when info.rxFlowNo == nil
 -- reversePacket = false
 local reversePacket = false
 if info.rxFlowNo ~= nil then
    if info.rxIsForward == percc1.IS_FORWARD and
       info.rxIsExit == percc1.IS_EXIT then
       pendingFinAck = true
    end
    if info.rxIsForward == percc1.IS_FORWARD then
       reversePacket = true
    end
 end

 -- application mustn't issue an end, before we've gotten
 -- even one control packet back
 assert(not(pendingFin[flowId] ~= nil and info.rxFlowNo == nil))
 
 if (pendingFin[flowId] ~= nil) or pendingFinAck then
   --  if (not reversePacket) then
   --     print(now .. ": Marking exit packet for " .. flowId .. " at source " .. self.id)
   --  else
   --     print(now .. ": Marking exit packet for " .. flowId .. " at destination " .. self.id)
   --  end
   -- print("Since pendingFin was " .. tostring(pendingFin[flowId]))
   -- print(" and pendingFinAck was " .. tostring(pendingFinAck))
   pkt.percc1:setIsExit(percc1.IS_EXIT)
   pendingFin[flowId] = nil
   else pkt.percc1:setIsExit(percc1.IS_NOT_EXIT) end
 

 if (reversePacket) then
    pkt.percc1:setIsForward(percc1.IS_NOT_FORWARD)
 else pkt.percc1:setIsForward(percc1.IS_FORWARD) end
end

return EndHost
