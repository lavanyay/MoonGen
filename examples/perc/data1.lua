local ffi = require("ffi")
local pkt = require("packet")
local dpdk	= require "dpdk"
local dpdkc	= require "dpdkc"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local pipe		= require "pipe"
local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"
local pcap = require "pcap"
local ipc = require "examples.perc.ipc"
local monitor = require "examples.perc.monitor"
local perc_constants = require "examples.perc.constants"
local DATA_PACKET_SIZE	= perc_constants.DATA_PACKET_SIZE -- includes payload
local ACK_PACKET_SIZE = perc_constants.ACK_PACKET_SIZE

data1Mod = {}

function data1Mod.log(str)
   if perc_constants.LOG_DATA then
      print(str)
   end
end

function data1Mod.dataSlave(dev, pipes, readyInfo, monitorPipe)
   data1Mod.log("starting dataSlave on " .. dpdk.getCore())
	-- one counter for total data throughput

	ipc.waitTillReady(readyInfo)

	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = DATA_PACKET_SIZE,
			ethSrc = 0,
			ethDst = "10:11:12:13:14:15", -- ready info id??
			ip4Dst = "192.168.1.1",
			udpSrc = 0, -- flow id
			udpDst = 0, -- packets left	
				       }
	end)
	mem:retain()
	
	local ackMem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = ACK_PACKET_SIZE,
			ethSrc = perc_constants.ACK_QUEUE,
			ethDst = "10:11:12:13:14:15", -- ready info id??
			ip4Dst = "192.168.1.1",
			udpSrc = 0, -- flow id
			udpDst = 0, -- packets received
				       }
	end)
	ackMem:retain()
	
	-- state for tx
	-- numPacketsLeft[flow]
	-- queue[flow]
	-- txBufs
	-- rxCtr
	local numPacketsSent = {}
	local numPacketsLeft = {}
	local numPacketsAcked = {}
	local numPacketsCommitted = {} -- to app
	local numPacketsTotal = {}

	local queues = {}
	local txBufs = mem:bufArray(128)
	local txBufsAck = ackMem:bufArray(128) 
	local txCtr = stats:newDevTxCounter(dev, "plain", ("tx_throughput-log-data-".. dev.id .. ".txt"))
	--local txCtr = stats:newDevTxCounter(dev, "plain")
	
	-- state for rx
	-- numPacketsReceived[flow]
	-- rxBufs
	-- txCtr
	local numPacketsReceived = {} -- flows to number of packets received
	local maxSeqReceived = {}
	local rxBufs = memory.bufArray() -- to receive data packets
	local rxBufsAck = memory.bufArray()
	local rxQueue = dev:getRxQueue(perc_constants.DATA_RXQUEUE)
	local rxQueueAck = dev:getRxQueue(perc_constants.ACK_QUEUE) -- special queue for Ack, JLT
	local txQueueAck = dev:getTxQueue(perc_constants.ACK_QUEUE) -- special queue for Ack, JLT
	--local rxCtr = stats:newDevRxCounter(dev, "plain")

	local numLoopsSinceStart = 0
	local lastLoggedDpdkLoopStartTime = 0
	
	local corruptedDataPkts = 0

	local numTxDataPacketsSinceLog = 0
	local numRxDataPacketsSinceLog = 0
	local numTxAckPacketsSinceLog = 0
	local numRxAckPacketsSinceLog = 0

	local numActiveQueues = 0
	while dpdk.running() do	   
	   local dpdkLoopStartTime = dpdk.getTime()
	   numLoopsSinceStart = numLoopsSinceStart + 1

	   if monitorPipe ~= nil and
	   numLoopsSinceStart % monitor.constDataNumLoops == 0 then
	      monitorPipe:send(
		 ffi.new("genericMsg",
			 {["valid"]= 1234,
			    ["time"]= dpdkLoopStartTime,
			    ["msgType"]= monitor.typeDataStatsPerDpdkLoop,
			    ["d1"]= (dpdkLoopStartTime
					  - lastLoggedDpdkLoopStartTime),
			    ["d2"]= numTxDataPacketsSinceLog,
			    ["i1"]= numRxDataPacketsSinceLog,
			    ["i2"]= numTxAckPacketsSinceLog,
			    ["loop"]=numRxAckPacketsSinceLog
	      }))
	      numTxDataPacketsSinceLog = 0
	      numRxDataPacketsSinceLog = 0
	      numTxAckPacketsSinceLog = 0
	      numRxAckPacketsSinceLog = 0
	      lastLoggedDpdkLoopStartTime = dpdkLoopStartTime
	   end

	   do -- NEW FLOWS TO SEND
	      local msgs = ipc.acceptFcdStartMsgs(pipes)
	      if next(msgs) ~= nil then
		 -- data1Mod.log("dataSlave: accepted FcdStartMsgs")
		 for msgNo, msg in pairs(msgs) do
		    assert(msg.flow >= 100)
		    assert(numPacketsLeft[msg.flow] == nil)
		    assert(queues[msg.flow] == nil)
		    numPacketsTotal[msg.flow] = msg.size
		    numPacketsLeft[msg.flow] = msg.size
		    numPacketsSent[msg.flow] = 0
		    numPacketsAcked[msg.flow] = 0
		    numPacketsCommitted[msg.flow] = 0
		    queues[msg.flow] = msg.queue
		    numActiveQueues = numActiveQueues + 1
		    -- data1Mod.log("dataSlave: new flow " .. msg.flow .. " of size " .. msg.size .. " on queue " .. msg.queue)
		 end
		 if monitorPipe ~= nil then
		    monitorPipe:send(
		       ffi.new("genericMsg",
			       {["valid"]= 1234,
				  ["i1"]= numActiveQueues,
				  ["msgType"]= monitor.typeNumActiveQueues,
				  ["time"]= now }))
		 end

	      end -- ends if next(msgs)..
	   end

	   do -- SEND DATA PACKETS
	      local atLeastOneFlowEnded = false
	      local now = dpdk.getTime()
	      for flow, queueNo in pairs(queues) do
		 local numLeft = numPacketsLeft[flow]
		 local numSent = numPacketsSent[flow]
		 --data1Mod.log("Flow " .. flow .. " has " .. numLeft .. " left to send.\n")
		 assert(numLeft >= 0)	      

		 local numToSend = 128
		 if numLeft < 128 then numToSend = numLeft end
		 txBufs:allocN(DATA_PACKET_SIZE, numToSend)
		 for i=1,numToSend do		 
		    local pkt = txBufs[i]:getUdpPacket()
		    assert(pkt.eth:getType() == eth.TYPE_IP)
		    assert(flow == tonumber(flow))
		    pkt.udp:setSrcPort(tonumber(flow))
		    pkt.udp:setDstPort(numSent+i)
		    pkt.payload.uint16[0]= flow
		    pkt.payload.uint16[1]= numSent+i
		    pkt.payload.uint16[2]= math.random(0, 2^16 - 1)
		    pkt.payload.uint16[3]= numLoopsSinceStart
		    local customChecksum = checksum(pkt.payload,8)
		    -- data1Mod.log("\nChecksum for transmitted packet (got "
		    --  	     .. customChecksum .. ")\n")

		    pkt.udp:setChecksum(customChecksum)
		    pkt.eth.src:set(queueNo)
		 end
		 -- TODO(lav): BUG where packet with same seqNum
		 --  received multiple times
		 --txBufs:offloadUdpChecksums()
		 assert(txBufs.size == numToSend)

		 local numSentNow = 0

		 if numLoopsSinceStart % 100 > monitor.constDataSamplePc then
		    -- in the common case, want to loop in C till
		    -- all packets are transmitted, since our
		    -- while loop isn't tight and we've already spent
		    -- too much time dilly-dallying around data
		    -- packets without actuall sending them
		    numSentNow = dev:getTxQueue(queueNo):send(txBufs)
		 else
		 -- if we want to sample queue size, should do
		 -- rte_eth_tx_burst and see how many packets descriptors
		 -- we can put on ring..
		    numSentNow = dpdkc.rte_eth_tx_burst_export(
		       dev.id, queueNo, txBufs.array, txBufs.size
		    )
		    if monitorPipe ~= nil then
		       monitorPipe:send(
			  ffi.new("genericMsg",
				  {["valid"]= 1234,
				     ["i1"]= queueNo,
				     ["i2"]= flow,
				     ["d1"]= numSentNow,
				     ["d2"]=txBufs.size,
				     ["msgType"]= monitor.typeDataQueueSize,
				     ["time"]= now }))
		    end
		 end
		 -- corrupt every mbuf udp packet ... doesn't help
		 -- still see dup data packets
		 -- for i=1,txBufs.size do
		 --    txBufs[i]:getUdpPacket().udp:setChecksum(0)
		 -- end
		 txBufs:freeAll()

		 numTxDataPacketsSinceLog = numTxDataPacketsSinceLog
		    + numSentNow
		 
		 numLeft = numLeft - numSentNow
		 --data1Mod.log("Sent " .. numSentNow .. " data packets of flow " .. flow
		 --	  .. ", " .. numLeft .. " to go")
		 assert(numLeft >= 0)	      
		 numPacketsLeft[flow] = numLeft
		 numPacketsSent[flow] = numSent + numSentNow
		 if (numLeft == 0) then
		    atleastOneFlowEnded = true
		    numPacketsLeft[flow] = nil
		    queues[flow] = nil
		    numActiveQueues = numActiveQueues - 1
		    -- no more sending
		    ipc.sendFdcFinMsg(pipes, flow, now)
		 end	      
	      end -- ends for flow, queueNo in queues

	      if atLeastOneFlowEnded then
		 monitorPipe:send(
		    ffi.new("genericMsg",
			    {["valid"]= 1234,
			       ["i1"]= numActiveQueues,
			       ["msgType"]= monitor.typeNumActiveQueues,
			       ["time"]= now }))
	      end
	      -- also need to send ACKs for received packets
	   end

	   do -- RECEIVE DATA PACKETS AND SEND ACKS
	      local numAcks = 0 -- actually Acks, one per flow
	      local ackPending = {}

	      do -- RECEIVE DATA PACKETS
		 local now = dpdk.getTime()
		 local rx = rxQueue:tryRecv(rxBufs, 128)
		 
		 if (rx > 0) then
		    -- data1Mod.log("Received " .. rx .. " data packets")
		    numRxDataPacketsSinceLog = numRxDataPacketsSinceLog + rx
		 end
		 for i = 1, rx do
		    local buf = rxBufs[i]
		    local pkt = buf:getUdpPacket()
		    assert(pkt.eth:getType() == eth.TYPE_IP)
		    local receivedChecksum = pkt.udp:getChecksum()
		    local customChecksum = checksum(pkt.payload, 8)
		    -- data1Mod.log("\nChecksum for received packet (got "
		    --  	     .. receivedChecksum .. " and calculated "
		    --  	     .. customChecksum .. ")\n")
		    local flowId = pkt.udp:getSrcPort()
		    local seqNum = pkt.udp:getDstPort()
		    --local left = pkt.udp:getDstPort() --not used anywhere
		    if (customChecksum == receivedChecksum) then	
		       -- TODO(lav): hack to make sure this isn't re-used
		       pkt.udp:setChecksum(0) 
		       if numPacketsReceived[flowId] == nil then	
			  numPacketsReceived[flowId] = 0
		       end

		       data1Mod.log("Received flowId: "
				.. flowId
				.. " seqNum " .. seqNum
				.. " random " .. pkt.payload.uint16[2]
				.. " queueNo " .. pkt.payload.uint16[3]
				.. " checksum " .. customChecksum			     
				.. " numPacketsReceived " .. numPacketsReceived[flowId])

		       if (maxSeqReceived[flowId] == nil
			   or seqNum > maxSeqReceived[flowId]) then
			  maxSeqReceived[flowId] = seqNum
		       end
		       
		       numPacketsReceived[flowId] = numPacketsReceived[flowId] + 1

		       -- TODO(lav): BUG where packet with same seqNum
		       --  received multiple times and assert fails
		       -- assert(maxSeqReceived[flowId] >= numPacketsReceived[flowId])
		       
		       if ackPending[flowId] == nil then
			  ackPending[flowId] = true --numPacketsReceived[flowId]
			  numAcks = numAcks + 1
		       end		 
		    else
		       corruptedDataPkts = corruptedDataPkts + 1		    
		       --data1Mod.log("Received corrupted UDP message.\n")
		    end
		 end
		 rxBufs:freeAll()	
	      end -- do
	      --rxCtr:update()

	      do -- SEND ACKS
		 if numAcks > 0 then
		    -- SEND ACKS, received on a different queue
		    txBufsAck:allocN(ACK_PACKET_SIZE, numAcks)
		    local bufNo = 1
		    for flowId, xx in pairs(ackPending) do
		       local numPackets = numPacketsReceived[flowId] 
		       assert(bufNo <= numAcks)
		       local pkt = txBufsAck[bufNo]:getUdpPacket()
		       pkt.udp:setSrcPort(flowId)
		       pkt.udp:setDstPort(numPackets)
		       pkt.eth:setType(eth.TYPE_ACK) -- filter into separate queue
		       local customChecksum = checksum(pkt.udp,6)
		       pkt.udp:setChecksum(customChecksum)
		       pkt.eth.src:set(perc_constants.ACK_QUEUE)
		       --data1Mod.log("data " .. readyInfo.id .. " sending ACK for " .. flowId)
		       bufNo = bufNo + 1
		    end
		    assert(bufNo == numAcks+1)
		    --local numSent = txQueueAck:sendN(txBufsAck, numAcks)
		    local numSent = dpdkc.rte_eth_tx_burst_export(
		       dev.id, perc_constants.ACK_QUEUE, txBufsAck.array, numAcks
		    ) -- may not send all pending acks..		    
		    numTxAckPacketsSinceLog = numTxAckPacketsSinceLog + numSent
		    txBufsAck:freeAll()
		    --data1Mod.log("data " .. readyInfo.id .. " sent " .. numSent .. " of "
		    --	       .. numAcks .. " pending Acks.")
		 end
	      end
	   end -- RECEIVE DATA AND SEND ACKS
	   
	   do -- RECEIVE ACKS
	      -- this is where we update packetsAcked
	      -- notifying app for every 10% of total packets
	      local now = dpdk.getTime()
	      -- wait for 128us??
	      local rx = rxQueueAck:tryRecv(rxBufsAck, 128)
	      if (rx > 0) then
		 -- data1Mod.log("Received " .. rx .. " ack packets")
		 numRxAckPacketsSinceLog = numRxAckPacketsSinceLog + rx
	      end
	      
	      for i = 1, rx do	      
		 local buf = rxBufsAck[i]
		 local pkt = buf:getUdpPacket()
		 local flowId = pkt.udp:getSrcPort()
		 local acked = pkt.udp:getDstPort()
		 assert(pkt.eth:getType() == eth.TYPE_ACK)
		 local customChecksum = checksum(pkt.udp, 6)
		 if (customChecksum == pkt.udp:getChecksum()) then
		    assert(numPacketsTotal[flowId] ~= nil)
		    if acked > numPacketsAcked[flowId] then
		       numPacketsAcked[flowId] = acked
		       local committed = numPacketsCommitted[flowId]
		       local total = numPacketsTotal[flowId]
		       if (total < 10
			      or (acked - committed) > 0.1 * total
			   or acked > 0.9 * total) then 
			  ipc.sendFdcFinAckMsg(pipes, flowId, acked, now)
			  numPacketsCommitted[flowId] = acked
			  data1Mod.log("data " .. readyInfo.id .. " got ACK ( "
				   .. acked
				   .. " / " .. total
				.. " ) for " .. flowId)			  
		       end
		       --data1Mod.log("data " .. readyInfo.id .. " got ACK for " .. flowId)
		    end
		 end
	      end
	      rxBufsAck:freeAll()
	   end -- do
	   
	   -- TODO(lav): garbage collect flowIds that are > 100 older
	   --  and discard any related packets..
	   txCtr:update()

	   if (numLoopsSinceStart % monitor.constDataNumLoops == 0) then
	      if monitorPipe ~= nil then
		 monitorPipe:send(
		    ffi.new("genericMsg",
			    {["valid"]= 1234,
			       ["i1"]= corruptedDataPkts,
			       ["msgType"]= monitor.typeCorruptedDataPkts,
			       ["time"]= now }))
	      end
	   end	   
	end -- ends while dpdk.running()
	txCtr:finalize()
	--rxCtr:finalize()
end

return data1Mod
