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

ffi.Cdef [[
struct rateInfo {
double currentRate, nextRate;
double changeTime;
}
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
   tmp = pkt.percg:getDestination()
   pkt.percg:setDestination(pkt.eth:getSource())
   pkt.percg:setSource(tmp)

   -- get maxHops, then smallest index, two rates
   local maxHops = pkt.percc1:getHop()
   if (pkt.percc1:getIsForward() ~= percg.IS_FORWARD) then
      maxHops = pkt.percc1:getMaxHops()
   end
   local bnInfo = pkt.percc1:getBottleneckInfo(maxHops)
   local bnRate1, bnRate2 = bnInfo.bnRate1, bnInfo.bnRate2   
   local bnBitmap = bnInfo.bitmap
   -- then set rate at each index
   -- and unsat/ sat at each index
   --pkt.percg:setRatesAndLabelGivenBottleneck(rate, hop, maxHops)	      
   for i=1,maxHops do		 
      pkt.percc1:setOldLabel(i, pkt.percc1:getNewLabel(i))
      pkt.percc1:setOldRate(i,  pkt.percc1:getNewRate(i))
      if bnBitmap[i] ~= 1 then
	 pkt.percc1:setNewLabel(i, percc.LABEL_SAT)
	 pkt.percc1:setNewRate(i,  bnRate1)
      else
	 pkt.percc1:setLabel(bnIndex, percc.LABEL_UNSAT)
	 pkt.percc1:setRate(bnIndex, bnRate2)
      end
   end
   pkt.percc1:setMaxHops(maxHops) -- and hop is the same
   if (pkt.percc1:getIsForward() ~= percg.IS_FORWARD) then      
      pkt.percc1:setIsForward(percg.IS_FORWARD)
   else
      pkt.percc1:setIsForward(percg.IS_NOT_FORWARD)
   end
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
	local txQueue = dev:getTxQueue(0)

	local queues = {}
	for i=0, 127 do
	   if (127-i) ~= 0 then 
	      table.insert(self.freeQueues, 127-i)
	   end
	end

	local rateInfo = {}
	local queueRates = {}
	local pendingChangeRate = {}
	
	local newBufs = memory.bufArray(100)
	local bufs = memory.bufArray()

	ipc.waitTillReady(readyInfo)
	
	while dpdk.running() do

	   -- echoes received packets
	   local rx = rxQueue:tryRecv(bufs, 128)
	   for i = 1, rx do
	      local pkt = bufs[i]:getPercc1Packet()
	      local tmp = pkt.eth:getDst()
	      pkt.eth:setDst(pkt.eth:getSrc())
	      pkt.eth:setSrc(tmp)
	      -- handle differently at receiver and source
	      -- receiver simply processes and echoes, FIN or not
	      if pkt.percc1:getIsForward() == percg.IS_FORWARD then
		 self.percc1ProcessAndGetRate(pkt)
	      else
		 -- source doesn't reply to FIN
		 -- will set FIN for flows that ended
		 -- will update rates otherwise
		 if pkt.percc1:getIsExit() == percg.IS_EXIT then -- receiver echoed fin		 
		    pkt.eth:setSrc(-1)		    
		 elseif queues[flow] == nil then -- flow ended
		    self.percc1ProcessAndGetRate(pkt)
		    pkt.percc1:setIsExit(percg.IS_EXIT)	      
		 else -- flow hasn't ended yet, update rates
		    local rate1 = self.percc1ProcessAndGetRate(pkt)
		    assert(rate1 ~= nil)
		    local queueNo = queues[flowId]
		    assert(queueNo ~= nil)
		    local rateInfo = queueRates[queueNo]
		    -- should setup with queue
		    -- initilize to current = 0, next, changeTime = nil
		    assert(rateInfo ~= nil)		    
		    if rate1 ~= rateInfo.current then
		       if rate1 < rateInfo.current then
			  rateInfo.current = rate1
			  rateInfo.next = nil
			  rateInfo.changeTime = nil
			  -- txDev:setRate ..
			  dev:getTxQueue(queueNo):setRate(rate1)
		       else -- rate1 > rateInfo.current
			  if rateInfo.next == nil then
			     rateInfo.next = rate
			     rateInfo.changeTime = now + 2
			  elseif rate1 < rateInfo.next then
			     rateInfo.next = rate1
			     -- leave changeTime as is
			  else -- rate1 > rateInfo.next
			     rateInfo.next = rate1
			     rateInfo.changeTime = now + 2
			     -- reset changeTime
			  end
		       end -- if rate1 < current else if etc. etc.
		    end -- if rate1 is different from current
		 end -- if packet at recevier/ source etc. etc.
	   end -- for i = 1, rx
	   txQueue:sendN(bufs, rx)

	   -- makes new packets
	   local msgs = ipc.acceptFacStartMsgs(pipes)
	   if msgs ~= nil then
	      local numNew = 0
	      for msgNo, msg in pairs(msgs) do
		 -- get a queue and queueRates state
		 if next(freeQueues) ~= nil then
		    local flowId = msg.flow
		    assert(queues[flowId] == nil)
		    local queue = table.remove(freeQueues)
		    queues[flowId] = queue

		    queueRates[flowId] = ffi.C.new("rateInfo")
		    queueRates[flowId].currentRate = 0
		    queueRates[flowId].nextRate = nil
		    queueRates[flowId].changeTime = nil

		    assert(numNew < 100) -- we only have 100 mbufs for new packets
		    numNew = numNew + 1
		    -- tell data thread
		    ipc.sendFcdStartMsg(pipes, msg.flow,
					msg.destination, msg.size, queue)		 
		 
		    -- fill new packet
		    local pkt = newBufs[numNew]:getPercc1Packet()
		    --pkt.eth:setDestination(xx)
		    pkt.percg:setFlowId(flowId)
		    pkt.percg:setDestination(msg.destination)
		    pkt.percc1:setIsForward(percc1.IS_FORWARD) -- default NOT
		    -- everything else is default for new packet
		    end
	      end
	      txQueue:sendN(newBufs, numNew)
	   end

	   -- deallocates queues for completed flows
	   local msgs = ipc.acceptFdcEndMsgs(pipes)
	   if msgs ~= nil then
	      for msgNo, msg in pairs(msgs) do
		 local flowId = msg.flow
		 local queueNo = queues[flowId]
		 assert(queueNo ~= nil)
		 queueRates[queueNo] = nil
		 table.insert(freeQueues, queueNo)
		 queues[flowId] =  nil
	      end
	   end

	   -- change rates of active flows if it's time
	   for queueNo, rateInfo in pairs(self.queueRates) do
	      if rateInfo.changeTime ~= nil and ratesInfo.changeTime <= now then
		 rateInfo.current = rateInfo.next
		 rateInfo.next = nil
		 rateInfo.changeTime = nil
		 dev:getTxQueue(queueNo):setRate(rateInfo.current)
	      end

	end -- while dpdk.running()	
	dpdk.sleepMillis(5000)
end


return control2Mod
