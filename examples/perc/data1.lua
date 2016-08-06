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
local PKT_SIZE	= 1500
local ACK_SIZE = 128

data1Mod = {}


function data1Mod.dataSlave(dev, pipes, readyInfo, monitorPipe)
   print("starting dataSlave on " .. dpdk.getCore())
	-- one counter for total data throughput

	ipc.waitTillReady(readyInfo)

	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = PKT_SIZE,
			ethSrc = 0,
			ethDst = "10:11:12:13:14:15", -- ready info id??
			ip4Dst = "192.168.1.1",
			udpSrc = 0, -- flow id
			udpDst = 0, -- packets left	
				       }
	end)

	local ackMem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = ACK_SIZE,
			ethSrc = perc_constants.ACK_QUEUE,
			ethDst = "10:11:12:13:14:15", -- ready info id??
			ip4Dst = "192.168.1.1",
			udpSrc = 0, -- flow id
			udpDst = 0, -- packets received
				       }
	end)

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

	local dpdkLoopCounter = 0
	local corruptedDataPkts = 0

	while dpdk.running() do	   
	   local now = dpdk.getTime()

	   
	   do -- NEW FLOWS TO SEND
	      local msgs = ipc.acceptFcdStartMsgs(pipes)
	      if next(msgs) ~= nil then
		 -- print("dataSlave: accepted FcdStartMsgs")
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
		    -- print("dataSlave: new flow " .. msg.flow .. " of size " .. msg.size .. " on queue " .. msg.queue)
		 end		
	      end -- ends if next(msgs)..
	   end

	   do -- SEND DATA PACKETS
	      for flow, queueNo in pairs(queues) do
		 local numLeft = numPacketsLeft[flow]
		 local numSent = numPacketsSent[flow]
		 --print("Flow " .. flow .. " has " .. numLeft .. " left to send.\n")
		 assert(numLeft >= 0)	      
		 local queue = dev:getTxQueue(queueNo)		 
		 local numToSend = 128
		 if numLeft < 128 then numToSend = numLeft end
		 txBufs:allocN(PKT_SIZE, numToSend)
		 for i=1,numToSend do		 
		    local pkt = txBufs[i]:getUdpPacket()
		    assert(pkt.eth:getType() == eth.TYPE_IP)
		    assert(flow == tonumber(flow))
		    pkt.udp:setSrcPort(tonumber(flow))
		    pkt.udp:setDstPort(numSent+i)
		    pkt.payload.uint16[0]= flow
		    pkt.payload.uint16[1]= numSent+i
		    pkt.payload.uint16[2]= math.random(0, 2^16 - 1)
		    local customChecksum = checksum(pkt.payload,6)
		    -- print("\nChecksum for transmitted packet (got "
		    --  	     .. customChecksum .. ")\n")

		    pkt.udp:setChecksum(customChecksum)
		    pkt.eth.src:set(queueNo)
		 end
		 -- TODO(lav): BUG where packet with same seqNum
		 --  received multiple times
		 --txBufs:offloadUdpChecksums()
		 local numSentNow = queue:trySendN(txBufs, numToSend)
		 numLeft = numLeft - numSentNow
		 --print("Sent " .. numSentNow .. " data packets of flow " .. flow
		 --	  .. ", " .. numLeft .. " to go")
		 assert(numLeft >= 0)	      
		 numPacketsLeft[flow] = numLeft
		 numPacketsSent[flow] = numSent + numSentNow
		 if (numLeft == 0) then
		    local now = dpdk.getTime()
		    numPacketsLeft[flow] = nil
		    queues[flow] = nil
		    -- no more sending
		    ipc.sendFdcFinMsg(pipes, flow, now)
		 end	      
	      end -- ends for flow, queueNo in queues
	      -- also need to send ACKs for received packets
	   end

	   do -- RECEIVE DATA PACKETS AND SEND ACKS
	      local numAcks = 0 -- actually Acks, one per flow
	      local ackPending = {}

	      do -- RECEIVE DATA PACKETS
		 local now = dpdk.getTime()
		 local rx = rxQueue:tryRecv(rxBufs, 128)
		 --if (rx > 0) then print("Received " .. rx .. " data packets") end
		 for i = 1, rx do
		    local buf = rxBufs[i]
		    local pkt = buf:getUdpPacket()
		    assert(pkt.eth:getType() == eth.TYPE_IP)
		    local receivedChecksum = pkt.udp:getChecksum()
		    local customChecksum = checksum(pkt.payload, 6)
		    -- print("\nChecksum for received packet (got "
		    --  	     .. receivedChecksum .. " and calculated "
		    --  	     .. customChecksum .. ")\n")
		    local flowId = pkt.udp:getSrcPort()
		    local seqNum = pkt.udp:getDstPort()
		    --local left = pkt.udp:getDstPort() --not used anywhere
		    if (customChecksum == receivedChecksum) then	
		       -- print("Received original data packet on rxQueue at " .. readyInfo.id)
		       if numPacketsReceived[flowId] == nil then	
			  numPacketsReceived[flowId] = 0			  
		       end

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
		       if (corruptedDataPkts % 100 == 0) then
			  if monitorPipe ~= nil then
			     monitorPipe:send(
				ffi.new("genericMsg",
					{["valid"]= 1234,
					   ["i1"]= corruptedDataPkts,
					   ["msgType"]= monitor.typeCorruptedDataPkts,
					   ["time"]= now }))
			  end
		       end
		       --print("Received corrupted UDP message.\n")
		    end
		 end
		 rxBufs:freeAll()	
	      end -- do
	      --rxCtr:update()

	      do -- SEND ACKS
		 if numAcks > 0 then
		    -- SEND ACKS, received on a different queue
		    txBufsAck:allocN(ACK_SIZE, numAcks)
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
		       --print("data " .. readyInfo.id .. " sending ACK for " .. flowId)
		       bufNo = bufNo + 1
		    end
		    local numSent = txQueueAck:sendN(txBufsAck, numAcks)
		    --print("data " .. readyInfo.id .. " sent " .. numSent .. " of "
		    --	       .. numAcks .. " pending Acks.")
		 end
	      end
	   end -- RECEIVE DATA AND SEND ACKS
	   
	   do -- RECEIVE ACKS
	      --rxBufsAck:alloc(PKT_SIZE)
	      -- this is where we update packetsAcked
	      -- notifying app for every 10% of total packets
	      local now = dpdk.getTime()
	      local rx = rxQueueAck:tryRecv(rxBufsAck, 128)
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
			  print("data " .. readyInfo.id .. " got ACK ( "
				   .. acked
				   .. " / " .. total
				.. " ) for " .. flowId)
		       end
		       --print("data " .. readyInfo.id .. " got ACK for " .. flowId)
		    end
		 end
	      end
	      rxBufsAck:freeAll()
	   end -- do
	   
	   -- TODO(lav): garbage collect flowIds that are > 100 older
	   --  and discard any related packets..
	   txCtr:update()
	   dpdkLoopCounter = dpdkLoopCounter + 1
	end -- ends while dpdk.running()
	txCtr:finalize()
	--rxCtr:finalize()
end

return data1Mod
