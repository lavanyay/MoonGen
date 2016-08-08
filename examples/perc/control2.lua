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
local perc_constants = require "examples.perc.constants"
local monitor = require "examples.perc.monitor" 
local ipc = require "examples.perc.ipc"
local Link1 = require "examples.perc.perc_link"

local CONTROL_PACKET_SIZE	= perc_constants.CONTROL_PACKET_SIZE

control2Mod = {}

ffi.cdef [[
typedef struct {
double currentRate, nextRate;
double changeTime;
bool valid;
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

function control2Mod.log(str)
   if perc_constants.LOG_CONTROL then
      print(str)
   end
end

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
   -- control2Mod.log("At end host "
   -- 	 .. "\n  bottleneck rates are " .. bnRate1 .. " and " .. bnRate2
   -- 	 .. "\n  maxHops was " .. maxHops
   -- 	 .. "\n  bottleneck links are ..")
   -- for i=1,maxHops do
   --    if bnBitmap[i] == 1 then control2Mod.log(i .. " ") end
   -- end
   --   control2Mod.log("  setting rates etc. now")
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
	 -- control2Mod.log("setting new rate of " .. i
	 -- 	  .. " to " .. bnRate1)
      else
	 pkt.percc1:setNewLabel(i, percc1.LABEL_UNSAT)
	 pkt.percc1:setNewRate(i, bnRate2)
	 -- control2Mod.log("setting new rate of " .. i
	 -- 	  .. " to " .. bnRate2)
      end
   end -- for i=1,maxHops
   pkt.percc1:setMaxHops(maxHops) -- and hop is the same
   if (pkt.percc1:getIsForward() ~= percc1.IS_FORWARD) then
      --control2Mod.log("marking packet as forward")
      pkt.percc1:setIsForward(percc1.IS_FORWARD)
   else
      --control2Mod.log("marking packet as reverse")
      pkt.percc1:setIsForward(percc1.IS_NOT_FORWARD)
   end -- if (pkt.percc1:getIsForward() ..
   return bnRate1
end

function initializePercc1Packet(buf)
   buf:getPercc1Packet():fill{
      pktLength = CONTROL_PACKET_SIZE,
      percgSource = 0,
      percgDestination = 1, -- TO CHANGE
      percgFlowId = 0, -- TO CHANGE
      percgIsData = percg.PROTO_CONTROL,
      percc1IsForward = percc1.IS_FORWARD,
      percc1IsExit = percc1.IS_NOT_EXIT,
      percc1Hop = 0,
      percc1MaxHops = 0,
      ethSrc = 0,
      ethDst = "10:11:12:13:14:15",
      ethType = eth.TYPE_PERCG}
end

function control2Mod.controlSlave(dev, pipes, readyInfo, monitorPipe)
      local thisCore = dpdk.getCore()
      control2Mod.log("Running control slave on core " .. thisCore)

      local egressLink = Link1:new()
      
      -- create memory pool to be used by new control packets we'll tx
      -- Hmm(lav):
      --  1) setting custom bufSize -> segfault
      --  2) no limit to how many mbufs I can allocate without freeing
      --  3) allocated mbuf doesn't have fields initialized to default values
      --  (except I think mbuf from first alloc)
      local mem = memory.createMemPool{
	 --	    bufSize = CONTROL_PACKET_SIZE,
	 func = initializePercc1Packet
      }
      
      
      local lastRxTime = 0
      local lastTxTime = 0
      local rxQueue = dev:getRxQueue(perc_constants.CONTROL_QUEUE)
      assert(rxQueue ~= nil)
      local txQueue = dev:getTxQueue(perc_constants.CONTROL_QUEUE)
      assert(txQueue ~= nil)
      
      local freeQueues = {}
      -- what I really need is just flow id -> queue and queue -> config + flowId
      local queues = {}
      local queueRates = ffi.new("rateInfo[?]", 128)
      -- all but tx 1 for data
      for i=0, 127 do
	 if (127-i) ~= perc_constants.CONTROL_QUEUE
	    and (127-i) ~= perc_constants.ACK_QUEUE
	 and (127-i) ~= perc_constants.DROP_QUEUE then 
	    table.insert(freeQueues, 127-i)
	 end
	 queueRates[i].currentRate = 1
	 queueRates[i].nextRate = -1
	 queueRates[i].changeTime = -1
	 queueRates[i].valid = false
      end

      local pendingChangeRate = {}
	

      local bufs = memory.bufArray() -- to rx packets and modify and tx
      local newBufs = mem:bufArray(
	 perc_constants.NEW_FLOWS_PER_CONTROL_LOOP)
      -- for packets sent out for new flows
      -- only 2 mbufs at a time since I'm
      -- not expecting more than two new flows in a ~150us loop
      
      local noNewPackets = 0
      
       local lastPeriodic = dpdk.getTime()
       local numLoopsSinceStart = 0       
       local lastLoggedDpdkLoopStartTime = 0

       -- Hmm(lav) No limit to mbufs I can allocate
       -- without freeing: By default mempool is 2048 bufs
       -- large, and these newBufs once allocated
       -- from mempool are never freed. Then
       -- how am I able to allocate 200K membufs
       -- from the mempool??
       -- for i=1,100000 do
       -- 	  newBufs:alloc(CONTROL_PACKET_SIZE)
       -- end       
       -- print(newBufs[1]:getPercc1Packet().percc1:getHop())
       -- assert(false)

       ipc.waitTillReady(readyInfo)
       control2Mod.log("ready to start control2")

       while dpdk.running() do
	  local dpdkLoopStartTime = dpdk.getTime()
	  numLoopsSinceStart = numLoopsSinceStart + 1

	  
	  if monitorPipe ~= nil and numLoopsSinceStart % 100 == 0 then
	     monitorPipe:send(
		ffi.new("genericMsg",
			{["valid"]= 1234,
			   ["i1"]= numLoopsSinceStart,
			   ["msgType"]= monitor.typeControlDpdkLoopStartTime,
			   ["time"]= (dpdkLoopStartTime - lastLoggedDpdkLoopStartTime) * 1e3 }))
	     lastLoggedDpdkLoopStartTime = dpdkLoopStartTime
	  end

	  -- log actual data rates of all active queues every PERIOD
	  if dpdkLoopStartTime > lastPeriodic + perc_constants.LOG_EVERY_N_SECONDS then
	     lastPeriodic = dpdkLoopStartTime
	     for flowId, queueNo in pairs(queues) do
		assert(queueRates[queueNo].valid)
		local rateInfo = queueRates[queueNo]
		local dTxQueue = dev:getTxQueue(queueNo)
		local configuredRate = rateInfo.currentRate
		local actualRate = dTxQueue:getTxRate()			

		if monitorPipe ~= nil then
		   monitorPipe:send(
		      ffi.new("genericMsg",
			      {["i1"]= flowId,
				 ["d1"]= configuredRate,
				 ["d2"]= actualRate,
				 ["valid"]= 1234,
				 ["msgType"]= monitor.typeFlowTxRateConfigured,
				 ["time"]= lastPeriodic,
				 ["loop"]= numLoopsSinceStart
		   }))
		end
	     end
	  end
	  
	  -- echoes received packets
	  do
	     local rx = rxQueue:tryRecv(bufs, 128)
	     local now = dpdk.getTime()
	     for i = 1, rx do

		local pkt = bufs[i]:getPercc1Packet()
		pkt.percc1:doNtoh()

		if (i==1) then
		   print(readyInfo.id .. " got packet addressed to ethDst "
			 .. pkt.eth:getDst()) end
		-- ingress link processing for reverse packets
		if pkt.percc1:getIsForward() == percc1.IS_NOT_FORWARD then
		   control2Mod.log("\nRx-ing FlowId " .. pkt.percg:getFlowId()
		   	    .. " before ingress processing "
		   	    .. "\n" .. pkt.percg:getString()
		   	    ..  "\n  " .. pkt.percc1:getString())

		   egressLink:processPercc1Packet(pkt)		   

		   control2Mod.log("\nRx-ing FlowId " .. pkt.percg:getFlowId()
		   	    .. " after ingress processing "
		   	    .. "\n" .. pkt.percg:getString()
		   	    ..  "\n  " .. pkt.percc1:getString())
		end
		
		local tmp = pkt.eth:getDst()
		pkt.eth:setDst(pkt.eth:getSrc())
		pkt.eth:setSrc(tmp)
		-- handle differently at receiver and source
		-- receiver simply processes and echoes, FIN or not
		if pkt.percc1:getIsForward() == percc1.IS_FORWARD then
		   local flowId = pkt.percg:getFlowId()
		   assert(flowId >= 100)
		   --control2Mod.log("rx control gets pkt for flow " .. pkt.percg:getFlowId())
		   control2Mod.percc1ProcessAndGetRate(pkt)
		   if (pkt.percc1:getIsExit() == percc1.IS_EXIT) then
		      local ethType = pkt.eth:getType()
		      control2Mod.log("Flow " .. flowId
			       .. " " .. readyInfo.id
			       .. " received exit packet (marked fwd)"
			       .. " ethType is " .. ethType .. " vs DROP "
			       .. eth.TYPE_DROP
			       .. " leave unchanged and echo back")		  
		   end	       
		else
		   local flowId = pkt.percg:getFlowId()	       
		   assert(flowId >= 100)
		   -- source doesn't reply to FIN
		   -- will set FIN for flows that ended
		   -- will update rates otherwise
		   if pkt.percc1:getIsExit() == percc1.IS_EXIT then -- receiver echoed fin
		      --control2Mod.log("tx control gets exit pkt for flow " .. pkt.percg:getFlowId())
		      control2Mod.log("Flow " .. flowId
			       .. " " .. readyInfo.id .. " received exit packet (marked not fwd)"
			       .. " ethType is " .. pkt.eth:getType()
			       .. " set to DROP " .. eth.TYPE_DROP)
		      pkt.eth:setType(eth.TYPE_DROP)
		      
		   elseif queues[flowId] == nil then -- flow ended
		      --control2Mod.log("tx control gets regular pkt for no-more-data flow " .. pkt.percg:getFlowId())
		      control2Mod.percc1ProcessAndGetRate(pkt)
		      assert(pkt.percc1:getIsForward() == percc1.IS_FORWARD)
		      pkt.percc1:setIsExit(percc1.IS_EXIT)	      
		   else -- flow hasn't ended yet, update rates
		      --control2Mod.log("tx control gets regular pkt for have-more-data flow " .. pkt.percg:getFlowId())
		      local rate1 = control2Mod.percc1ProcessAndGetRate(pkt)
		      if monitorPipe ~= nil then
			 monitorPipe:send(
			    ffi.new("genericMsg",
				    {["i1"]= flowId,
				       ["d1"]= rate1,
				       ["valid"]= 1234,
				       ["msgType"]= monitor.typeGetFlowBottleneckRate,
				       ["time"]= now,
				       ["loop"]= numLoopsSinceStart
			 }))
		      end

		      assert(pkt.percc1:getIsForward() == percc1.IS_FORWARD)
		      assert(rate1 ~= nil)
		      local queueNo = queues[flowId]
		      --control2Mod.log("flow was assigned queue " .. queueNo)
		      assert(queueNo ~= nil)
		      local rateInfo = queueRates[queueNo]
		      -- should setup with queue
		      -- initilize to current = 0, next, changeTime = nil
		      assert(queueRates[queueNo].valid)		  
		      assert(rateInfo.currentRate >= 0)
		      if rate1 ~= rateInfo.currentRate then
			 if rate1 < rateInfo.currentRate then
			    control2Mod.log("Flow " .. flowId
				     .. "  received bottleneck rate " .. rate1
				     .. " is smaller than current " .. rateInfo.currentRate
				     .. " actually " .. dev:getTxQueue(queueNo):getTxRate())
			    rateInfo.currentRate = rate1
			    rateInfo.nextRate = -1
			    rateInfo.changeTime = -1
			    local dTxQueue = dev:getTxQueue(queueNo)
			    local configuredRate = rate1
			    dTxQueue:setRate(configuredRate)
			    if monitorPipe ~= nil then
			       monitorPipe:send(
				  ffi.new("genericMsg",
					  {["i1"]= flowId,
					     ["d1"]= configuredRate,
					     ["valid"]= 1234,
					     ["msgType"]= monitor.typeSetFlowTxRate,
					     ["time"]= now,
					     ["loop"]= numLoopsSinceStart
			       }))
			    end
			 else -- rate1 > rateInfo[0].currentRate
			    --control2Mod.log("  new rate " .. rate1 .. " is bigger than current " .. rateInfo.currentRate)
			    if rateInfo.nextRate == -1 then
			       rateInfo.nextRate = rate1
			       rateInfo.changeTime = now + 100e-6
			       control2Mod.log("Flow " .. flowId
					.. " received bottleneck rate " .. rate1
					.. " is bigger than current rate." 
					.. " No next rate scheduled, setting next rate to " .. rate1
					.. ", change at " .. rateInfo.changeTime .. "s ")
			    elseif rateInfo.nextRate == rate1 then
			       --control2Mod.log("     next rate is the same as new rate, do nothing")
			    elseif rateInfo.nextRate >= 0 and rate1 < rateInfo.nextRate then
			       control2Mod.log("Flow " .. flowId
					.. " received bottleneck rate " .. rate1
					.. " is bigger than current rate " 
					.. " and smaller than next rate " .. rateInfo.nextRate)
			       rateInfo.nextRate = rate1
			       -- leave changeTime as is
			    else -- rate1 > rateInfo.nextRate
			       control2Mod.log("Flow " .. flowId
					.. " received bottleneck rate " .. rate1
					.. " is bigger than current rate " 
					.. " also bigger than next rate " .. rateInfo.nextRate
					.. ", change at " .. now + 100e-6 .. "s ")
			       rateInfo.nextRate = rate1
			       rateInfo.changeTime = now + 100e-6
			       -- reset changeTime
			    end -- if rate1 < current else if etc. etc.
			 end
		      end -- if rate1 is different from current (rate update?)
		   end -- if pkt.percg.getIsExit ..(fin/ last/ echo?)	       
		   assert(pkt.percc1:getIsForward() == percc1.IS_FORWARD
			     or pkt.eth:getType() == eth.TYPE_DROP)
		end -- if packet is forward .. (receiver/ source?)


		-- egress link processing after sending out forward packets
		if (pkt.eth:getType() ~= eth.TYPE_DROP and
		    pkt.percc1:getIsForward() == percc1.IS_FORWARD) then
		   control2Mod.log("\nTx-ing FlowId " .. pkt.percg:getFlowId()
		   	    .. " before egress processing "
		   	    .. "\n" .. pkt.percg:getString()
		   	    ..  "\n  " .. pkt.percc1:getString())
		   
		   egressLink:processPercc1Packet(pkt)

		   control2Mod.log("\nTx-ing FlowId " .. pkt.percg:getFlowId()
		   	    .. " after egress processing "
		   	    .. "\n" .. pkt.percg:getString()
		   	    ..  "\n  " .. pkt.percc1:getString())
		end

		pkt.percc1:doHton()
	     end -- for i = 1, rx
	     txQueue:sendN(bufs, rx)
	  end -- do ECHOES RECEIVED PACKETS


	  do -- MAKES NEW PACKETS
	     -- makes new packets
	     local now = dpdk.getTime()
	     local msgs = ipc.fastAcceptMsgs(
		pipes, "fastPipeAppToControlStart",
		"pFacStartMsg", 20)
	     if next(msgs) ~= nil then
		newBufs:alloc(CONTROL_PACKET_SIZE)
		-- get two mbufs from the pool,
		-- these were initialized, freed once
		-- so fields should have default values
		noNewPackets = 0
		control2Mod.log("make  new packets")
		local numNew = 0
		for msgNo, msg in pairs(msgs) do
		   -- control2Mod.log("msg.flow " .. msg.flow .. ", msg.size " .. msg.size .. ", msg.destination " .. msg.destination)
		   -- get a queue and queueRates state
		   assert(next(freeQueues) ~= nil) -- TODO()
		   if next(freeQueues) ~= nil then 
		      local flowId = msg.flow
		      assert(flowId ~= nil)
		      assert(flowId >= 100)
		      assert(queues[flowId] == nil)
		      local queue = table.remove(freeQueues)
		      assert(queue ~= nil)
		      queues[flowId] = queue
		      queueRates[queue].valid = true
		      queueRates[queue].currentRate = 1
		      local configuredRate = queueRates[queue].currentRate
		      local dTxQueue = dev:getTxQueue(queue)
		      dTxQueue:setRate(configuredRate)
		      if monitorPipe ~= nil then
			 monitorPipe:send(
			    ffi.new("genericMsg",
				    {["i1"]= flowId,
				       ["d1"]= configuredRate,
				       ["valid"]= 1234,
				       ["msgType"]= monitor.typeSetFlowTxRate,
				       ["time"]= now,
				       ["loop"]= numLoopsSinceStart
			 }))
		      end		  
		      -- control2Mod.log("assigned a rateInfo struct for " .. flowId)
		      -- newBufs has only so many mbufs
		      assert(numNew <=
				perc_constants.NEW_FLOWS_PER_CONTROL_LOOP)
		      
		      numNew = numNew + 1
		      -- tell data thread
		      ipc.sendFcdStartMsg(pipes, msg.flow,
					  msg.destination,
					  msg.size, queue)

		      -- TODO(lav): remove after fixing the uninit. mbuf bug
		      initializePercc1Packet(newBufs[numNew]) -- re-initialized
		      local pkt = newBufs[numNew]:getPercc1Packet()
		      pkt.percg:setSource(readyInfo.id)
		      -- sanity checking that fields have default values
		      assert(pkt.percc1:getNumUnsat(1) == 0)
		      assert(pkt.percc1:getNumUnsat(2) == 0)

		      assert(flowId >= 100)
		      pkt.percg:setFlowId(flowId)
		      pkt.percg:setDestination(msg.destination)
		      pkt.eth:setDst(0x111111111111)
		      -- egress link processing after sending out
		      -- forward packets
		      if (pkt.eth:getType() ~= eth.TYPE_DROP and
			  pkt.percc1:getIsForward() == percc1.IS_FORWARD) then
			 control2Mod.log("\nTx-ing #1! FlowId "
					    .. pkt.percg:getFlowId()
					    .. " before egress processing "
					    .. "\n" .. pkt.percg:getString()
					    ..  "\n  "
					    .. pkt.percc1:getString())
		   
			 egressLink:processPercc1Packet(pkt)

			 control2Mod.log("\nTx-ing #1! FlowId "
					    .. pkt.percg:getFlowId()
					    .. " after egress processing "
					    .. "\n" .. pkt.percg:getString()
					    ..  "\n  "
					    .. pkt.percc1:getString())

		      end
		      pkt.percc1:doHton()
		      -- everything else is default for new packet
		   end -- if next(freeQueues)..
		end -- for msgNo, msg..
		txQueue:sendN(newBufs, numNew)
		--control2Mod.log("Sent " .. numNew .. " new packets")
	     else
		noNewPackets = noNewPackets + 1
		if (noNewPackets % 100000 == 0) then
		   control2Mod.log("No new packets: " .. noNewPackets .. " at time " .. dpdk.getTime())
		end
	     end -- if msgs ~= nil
	  end

	  do -- DEALLOCATE QUEUES
	     -- deallocates queues for completed flows
	     local msgs =
		ipc.fastAcceptMsgs(
		   pipes, "fastPipeDataToControlFin",
		   "pFdcFinMsg", 20) --ipc.acceptFdcEndMsgs(pipes)
	     if next(msgs) ~= nil then
		--control2Mod.log("deallocate queues from completed flows")
		for msgNo, msg in pairs(msgs) do
		   local flowId = msg.flow
		   assert(flowId >= 100)
		   local queueNo = queues[flowId]
		   assert(queueNo ~= nil)
		   queueRates[queueNo].valid = false
		   queueRates[queueNo].currentRate = 1
		   queueRates[queueNo].nextRate = -1
		   queueRates[queueNo].changeTime = -1
		   table.insert(freeQueues, queueNo)
		   queues[flowId] =  nil

		   if monitorPipe ~= nil then
		      monitorPipe:send(
			 ffi.new("genericMsg",
				 {["i1"]= flowId,
				    ["d1"]= 0, -- aka deallocate
				    ["valid"]= 1234,
				    ["msgType"]= monitor.typeSetFlowTxRate,
				    ["time"]= now,
				    ["loop"]= numLoopsSinceStart
		      }))
		   end
		   -- TODO(lav) : too many nows, maybe number them
		   ipc.sendFcaFinMsg(pipes, msg.flow, msg.endTime)
		   -- control2Mod.log("deallocated queue " .. queueNo .. " for flow " .. flowId)
		end
	     end
	  end -- do DEALLOCATE QUEUES

	  do -- CHANGE RATES
	     -- change rates of active flows if it's time
	     local now = dpdk.getTime()
	     for flowId, queueNo in pairs(queues) do
		assert(queueRates[queueNo].valid)
		if queueRates[queueNo].changeTime ~= -1
		and queueRates[queueNo].changeTime <= now then
		   control2Mod.log("change rates for flow " .. flowId
				      .. ", queue " .. queueNo
				      .. " from " ..
				      queueRates[queueNo].currentRate
				      .. " to "
				      .. queueRates[queueNo].nextRate)
		   queueRates[queueNo].currentRate
		      = queueRates[queueNo].nextRate
		   queueRates[queueNo].nextRate = -1
		   queueRates[queueNo].changeTime = -1

		   local configuredRate = queueRates[queueNo].currentRate
		   local dTxQueue = dev:getTxQueue(queueNo)
		   dTxQueue:setRate(configuredRate)

		   if monitorPipe ~= nil then
		      monitorPipe:send(
			 ffi.new("genericMsg",
				 {["i1"]= flowId,
				    ["d1"]= configuredRate,
				    ["valid"]= 1234,
				    ["msgType"]= monitor.typeSetFlowTxRate,
				    ["time"]= now,
				    ["loop"]= numLoopsSinceStart
		      }))
		   end

		end -- if rateInfo[0].changeTime ~= nil ..
	     end -- for queueNo, ..
	  end

	  do -- TELL APPLICATIONS ABOUT ACKS
	     -- tells applications about flows that finished data completely
	     local msgs = ipc.acceptFdcFinAckMsgs(pipes)
	     if next(msgs) ~= nil then
		--control2Mod.log("deallocate queues from completed flows")
		for msgNo, msg in pairs(msgs) do
		   ipc.sendFcaFinAckMsg(pipes, msg.flow, msg.size,
					msg.endTime)
		end
	     end
	  end
      end -- while dpdk.running()	
      dpdk.sleepMillis(5000)
end


return control2Mod
