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
local EndHost = require "examples.perc.end_host"

local PKT_SIZE	= 80

control2Mod = {}

ffi.cdef [[
typedef struct {
double currentRate, nextRate;
double changeTime;
} rateInfo;
]]
-- handles flow start messages from applications - to send first control, assign a free queue for data
-- handles flow completion message from "data slave", sends exit packet to free up bandwidth, reclaims queue
-- receives control packets on rx queue, computes new bottleneck info and sends out new packets
-- adjusts rates of data queues based on rxd control packets

-- TODO(lav)
-- can we make it even simpler, example rx some packets, modify them to get
-- packets to send (or drop), and add new packets for new flows.
-- and tx
-- then fetch new flows list and completed flows list.

function control2Mod.percc1ProcessAndGetRate(pkt)
   local tmp = pkt.percg:getDestination()
   pkt.percg:setDestination(pkt.percg:getSource())
   pkt.percg:setSource(tmp)

   -- get maxHops, then smallest index, two rates
   local maxHops = pkt.percc1:getHop()
   if (pkt.percc1:getIsForward() ~= percc1.IS_FORWARD) then
      maxHops = pkt.percc1:getMaxHops()
   end
   local bnInfo = pkt.percc1:getBottleneckInfo(maxHops)
   local bnRate1, bnRate2 = bnInfo.bnRate1, bnInfo.bnRate2   
   local bnBitmap = bnInfo.bnBitmap
   assert(bnRate1 ~= nil)
   assert(bnRate2 ~= nil)
   assert(bnBitmap ~= nil)
   -- then set rate at each index
   -- and unsat/ sat at each index
   --pkt.percg:setRatesAndLabelGivenBottleneck(rate, hop, maxHops)	      
   for i=1,maxHops do		 
      pkt.percc1:setOldLabel(i, pkt.percc1:getNewLabel(i))
      pkt.percc1:setOldRate(i,  pkt.percc1:getNewRate(i))
      if bnBitmap[i] ~= 1 then
	 pkt.percc1:setNewLabel(i, percc1.LABEL_SAT)
	 pkt.percc1:setNewRate(i,  bnRate1)
      else
	 pkt.percc1:setLabel(bnIndex, percc1.LABEL_UNSAT)
	 pkt.percc1:setRate(bnIndex, bnRate2)
      end
   end -- for i=1,maxHops
   pkt.percc1:setMaxHops(maxHops) -- and hop is the same
   if (pkt.percc1:getIsForward() ~= percc1.IS_FORWARD) then      
      pkt.percc1:setIsForward(percc1.IS_FORWARD)
   else
      pkt.percc1:setIsForward(percc1.IS_NOT_FORWARD)
   end -- if (pkt.percc1:getIsForward() ..
   return bnRate1
end

function control2Mod.controlSlave(dev, pipes, readyInfo)
      local thisCore = dpdk.getCore()
      print("Running control slave on core " .. thisCore)

	-- create memory pool to be used by new control packets we'll tx
	-- default values are most common values
	-- TODO(lav): ethSrc is source's MAC address (port 0/ ensf0) 
	--  and ethDst is ..
      local mem = memory.createMemPool(function(buf)
		buf:getPercc1Packet():fill{
		   pktLength = PKT_SIZE,
		   percgSource = readyInfo.id,
		   percgDestination = 1, -- TO CHANGE
		   percgFlowId = 0, -- TO CHANGE
		   percgIsData = percg.PROTO_CONTROL,
		   percc1IsForward = percc1.IS_FORWARD,
		   percc1IsExit = percc1.IS_NOT_EXIT,
		   percc1Hop = 0,
		   percc1MaxHops = 0,
		   ethSrc = 0,
		   ethDst = "10:11:12:13:14:15",	-- TO CHANGE					
		   ethType = eth.TYPE_PERCG
					  }
      end)
      endHost = EndHost.new(mem, dev, readyInfo.id, pipes, PKT_SIZE) 
      local lastRxTime = 0
      local lastTxTime = 0
      local rxQueue = dev:getRxQueue(0)
      assert(rxQueue ~= nil)
      local txQueue = dev:getTxQueue(0)
      assert(txQueue ~= nil)
      
      local freeQueues = {}
      local queues = {}
      for i=0, 127 do
	 if (127-i) ~= 0 then 
	    table.insert(freeQueues, 127-i)
	 end
      end

      local queueRates = {}
      local pendingChangeRate = {}
	
      local newBufs = mem:bufArray(100) -- for new packets
      local bufs = memory.bufArray() -- to rx packets and modify and tx

       ipc.waitTillReady(readyInfo)
      print("ready to start control2")
      while dpdk.running() do
	   -- echoes received packets
	 local rx = rxQueue:tryRecv(bufs, 128)
	 local now = dpdk.getTime()
	 for i = 1, rx do	    
	    --if i == 1 then print("handle " .. rx .. " received packets") end
	    local pkt = bufs[i]:getPercc1Packet()
	    pkt.percc1:doNtoh()
	    local tmp = pkt.eth:getDst()
	    pkt.eth:setDst(pkt.eth:getSrc())
	    pkt.eth:setSrc(tmp)
	    -- handle differently at receiver and source
	    -- receiver simply processes and echoes, FIN or not
	    if pkt.percc1:getIsForward() == percc1.IS_FORWARD then
	       assert(pkt.percg:getFlowId() >= 100)
	       control2Mod.percc1ProcessAndGetRate(pkt)
	    else
	       -- TOFIX(lav): V fails
	       assert(pkt.percg:getFlowId() >= 100)
	       -- source doesn't reply to FIN
	       -- will set FIN for flows that ended
	       -- will update rates otherwise
	       if pkt.percc1:getIsExit() == percc1.IS_EXIT then -- receiver echoed fin		 
		  pkt.eth:setSrc(-1)
		  ipc.sendMsgs(pipes, "slowPipeControlToApp",
			       {["msg"] = ("control end flow " .. pkt.percg:getFlowId()),
				  ["now"] = now})

	       elseif queues[flow] == nil then -- flow ended
		  control2Mod.percc1ProcessAndGetRate(pkt)
		  pkt.percc1:setIsExit(percc1.IS_EXIT)	      
	       else -- flow hasn't ended yet, update rates
		  local rate1 = control2Mod.percc1ProcessAndGetRate(pkt)		  
		    assert(rate1 ~= nil)
		    local queueNo = queues[flowId]
		    assert(queueNo ~= nil)
		    local rateInfo = queueRates[queueNo]
		    -- should setup with queue
		    -- initilize to current = 0, next, changeTime = nil
		    assert(rateInfo ~= nil)
		    assert(rateInfo[0].currentRate >= 0)
		    if rate1 ~= rateInfo[0].currentRate then
		       if rate1 < rateInfo[0].currentRate then
			  rateInfo[0].currentRate = rate1
			  rateInfo[0].nextRate = -1
			  rateInfo[0].changeTime = -1
			  -- txDev:setRate ..
			  dev:getTxQueue(queueNo):setRate(rate1)
		       else -- rate1 > rateInfo[0].currentRate
			  if rateInfo[0].nextRate == -1 then
			     rateInfo[0].nextRate = rate
			     rateInfo[0].changeTime = now + 2
			  elseif rateInfo[0].nextRate >= 0 and rate1 < rateInfo[0].nextRate then
			     rateInfo[0].nextRate = rate1
			     -- leave changeTime as is
			  else -- rate1 > rateInfo[0].nextRate
			     rateInfo[0].nextRate = rate1
			     rateInfo[0].changeTime = now + 2
			     -- reset changeTime
			  end -- if rate1 < current else if etc. etc.
		       end
		    end -- if rate1 is different from current (rate update?)
	       end -- if pkt.percg.getIsExit ..(fin/ last/ echo?)
	    end -- if packet is forward .. (receiver/ source?)
	    pkt.percc1:doHton()
	 end -- for i = 1, rx
	 txQueue:sendN(bufs, rx)

	 -- makes new packets
	 local msgs = ipc.acceptFacStartMsgs(pipes)
	 if next(msgs) ~= nil then
	    print("make  new packets")
	    newBufs:alloc(PKT_SIZE)
	    local numNew = 0
	    for msgNo, msg in pairs(msgs) do
	       -- get a queue and queueRates state
	       assert(next(freeQueues) ~= nil) -- TODO()
	       if next(freeQueues) ~= nil then 
		  local flowId = msg.flow
		  assert(flowId ~= nil)
		  assert(queues[flowId] == nil)
		  local queue = table.remove(freeQueues)
		  assert(queue ~= nil)
		  queues[flowId] = queue
		  print("assigned queue " .. queue .. " to " .. flowId)
		  
		  queueRates[flowId] = ffi.new("rateInfo[?]", 1)
		  queueRates[flowId][0].currentRate = 0
		  queueRates[flowId][0].nextRate = -1
		  queueRates[flowId][0].changeTime = -1
		  print("assigned a rateInfo struct for " .. flowId)
		  
		  assert(numNew < 100) -- we only have 100 mbufs for new packets
		  numNew = numNew + 1
		  -- tell data thread
		  ipc.sendFcdStartMsg(pipes, msg.flow,
				      msg.destination, msg.size, queue)		 
		  print("sent start msg to data for " .. msg.flow)
		  assert(numNew < 10)
		  -- fill new packet
		  local pkt = newBufs[numNew]:getPercc1Packet()
		  --pkt.eth:setDestination(xx)
		  assert(flowId >= 100)
		  pkt.percg:setFlowId(flowId)
		  pkt.percg:setDestination(msg.destination)
		  print("filled in new packet for " .. flowId)
		  pkt.percc1:doHton()
		  -- everything else is default for new packet
	       end -- if next(freeQueues)..
	    end -- for msgNo, msg..
	    txQueue:sendN(newBufs, numNew)
	    print("Sent " .. numNew .. " new packets")
	 end -- if msgs ~= nil
	 
	 -- deallocates queues for completed flows
	 local msgs = ipc.acceptFdcEndMsgs(pipes)
	 if next(msgs) ~= nil then
	    print("deallocate queues from completed flows")
	    for msgNo, msg in pairs(msgs) do
	       local flowId = msg.flow
	       assert(flowId >= 100)
	       local queueNo = queues[flowId]
	       assert(queueNo ~= nil) 
	       queueRates[queueNo] = nil
	       table.insert(freeQueues, queueNo)
	       queues[flowId] =  nil
	    end
	 end

	 -- change rates of active flows if it's time
	 local now = dpdk.getTime()
	 for queueNo, rateInfo in pairs(queueRates) do
	    assert(rateInfo ~= nil)
	    if rateInfo[0].changeTime ~= -1 and rateInfo[0].changeTime <= now then
	       print("change rates for queue " .. queueNo
			.. " from " .. rateInfo[0].currentRate
			.. " to " .. rateInfo[0].nextRate)
	       rateInfo[0].currentRate = rateInfo[0].nextRate
	       rateInfo[0].nextRate = -1
	       rateInfo[0].changeTime = -1
	       local dTxQueue = dev:getTxQueue(queueNo)
	       dTxQueue:setRate(rateInfo[0].currentRate)
	    end -- if rateInfo[0].changeTime ~= nil ..
	 end -- for queueNo, ..
	 
      end -- while dpdk.running()	
      dpdk.sleepMillis(5000)
end


return control2Mod
