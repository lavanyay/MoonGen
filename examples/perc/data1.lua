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
local perc_constants = require "examples.perc.constants"
local PKT_SIZE	= 1500

data1Mod = {}


function data1Mod.dataSlave(dev, pipes, readyInfo)
   print("starting dataSlave on " .. dpdk.getCore())
	-- one counter for total data throughput
	--local ctr = stats:newDevTxCounter(dev, "plain")
	ipc.waitTillReady(readyInfo)

	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = PKT_SIZE,
			ethSrc = queue,
			ethDst = "10:11:12:13:14:15", -- ready info id??
			ip4Dst = "192.168.1.1",
			udpSrc = 0, -- flow id
			udpDst = 0, -- packets left	
		}
	end)

	-- state for tx
	-- numPacketsLeft[flow]
	-- queue[flow]
	-- txBufs
	-- rxCtr
	local numPacketsLeft = {}
	local queues = {}
	local txBufs = mem:bufArray(128)
	local txBufsFinAck = mem:bufArray(128)
	local txCtr = stats:newDevTxCounter(dev, "plain")
	
	-- state for rx
	-- numPacketsReceived[flow]
	-- rxBufs
	-- txCtr
	local numPacketsReceived = {} -- flows to number of packets received
	local rxBufs = memory.bufArray() -- to receive data packets
	local rxBufsFinAck = memory.bufArray()
	local rxQueue = dev:getRxQueue(perc_constants.DATA_RXQUEUE)
	local rxQueueFinAck = dev:getRxQueue(perc_constants.FINACK_QUEUE)
	local txQueueFinAck = dev:getTxQueue(perc_constants.FINACK_QUEUE)
	local rxCtr = stats:newDevRxCounter(dev, "plain")

	local i = 0
	while dpdk.running() do	   
	   local now = dpdk.getTime()

	   -- NEW FLOWS TO SEND
	   local msgs = ipc.acceptFcdStartMsgs(pipes)
	   if next(msgs) ~= nil then
	      -- print("dataSlave: accepted FcdStartMsgs")
	      for msgNo, msg in pairs(msgs) do
		 assert(msg.flow >= 100)
		 assert(numPacketsLeft[msg.flow] == nil)
		 assert(queues[msg.flow] == nil)
		 numPacketsLeft[msg.flow] = msg.size
		 queues[msg.flow] = msg.queue
		 -- print("dataSlave: new flow " .. msg.flow .. " of size " .. msg.size .. " on queue " .. msg.queue)
	      end		
	   end -- ends if next(msgs)..

	   -- SENDING DATA PACKETS
	   for flow, queueNo in pairs(queues) do
	      local numLeft = numPacketsLeft[flow]
	      assert(numLeft >= 0)	      
	      local queue = dev:getTxQueue(queueNo)		 
	      local numToSend = 128
	      if numLeft < 128 then numToSend = numLeft end
	      txBufs:allocN(PKT_SIZE, numToSend)
	      for i=1,numToSend do		 
		 local pkt = txBufs[i]:getUdpPacket()
		 pkt.udp:setSrcPort(tonumber(flow))
		 pkt.udp:setDstPort(numLeft-i)
		 -- number of packets left, 0 for last packet
		 pkt.eth.src:set(queueNo)
	      end
	      txBufs:offloadUdpChecksums()
	      local numSent = queue:trySendN(txBufs, numToSend)
	      numLeft = numLeft - numSent
	      --print("Sent " .. numSent .. " data packets of flow " .. flow
	      -- 	       .. ", " .. numLeft .. " to go")
	      assert(numLeft >= 0)	      
	      numPacketsLeft[flow] = numLeft
	      if (numLeft == 0) then
		 local now = dpdk.getTime()
		 numPacketsLeft[flow] = nil
		 queues[flow] = nil
		 ipc.sendFdcFinMsg(pipes, flow, now)
	      end	      
	   end -- ends for flow, queueNo in queues
	   -- also need to send FIN-ACKs for received packets
	   --txCtr:update()
	   
	   -- RECEIVE DATA PACKETS
	   local rx = rxQueue:tryRecv(rxBufs, 128)
	   -- if (rx > 0) then print("Received " .. rx .. " data packets") end
	   local numFinAcks = 0
	   local finAckPending = {}
	   for i = 1, rx do
	      local buf = rxBufs[i]
	      local pkt = buf:getUdpPacket()
	      local flowId = pkt.udp:getSrcPort()
	      local left = pkt.udp:getDstPort()
	      if numPacketsReceived[flowId] == nil then	
		 numPacketsReceived[flowId] = 0
	      end
	      numPacketsReceived[flowId] = numPacketsReceived[flowId] + 1
	      if left == 0 then
		 local now = dpdk.getTime()
		 --print("Rx " .. numPacketsReceived[flowId]
		 -- 	  .. " packets of flow " .. flowId)
		 finAckPending[flowId] = numPacketsReceived[flowId]
		 numFinAcks = numFinAcks + 1
	      end
	   end
	   rxBufs:freeAll()	
	   --rxCtr:update()

	   
	   if numFinAcks > 0 then
	      -- SEND FIN-ACKS, received on a different queue
	      txBufsFinAck:allocN(PKT_SIZE, numFinAcks)
	      local bufNo = 1
	      for flowId, numPkts in pairs(finAckPending) do
		 assert(bufNo <= numFinAcks)
		 local pkt = txBufsFinAck[bufNo]:getUdpPacket()
		 pkt.udp:setSrcPort(flowId)
		 pkt.udp:setDstPort(numPkts)
		 pkt.eth:setType(eth.TYPE_FINACK) -- filter into separate queue
		 bufNo = bufNo + 1
	      end
	      local numSent = txQueueFinAck:sendN(txBufsFinAck, numFinAcks)
	   end

	   -- RECEIVE FIN-ACKS
	   --rxBufsFinAck:alloc(PKT_SIZE)	   
	   local rx = rxQueueFinAck:tryRecv(rxBufsFinAck, 128)
	   for i = 1, rx do	      
	      local now = dpdk.getTime()
	      local buf = rxBufsFinAck[i]
	      local pkt = buf:getUdpPacket()
	      local flowId = pkt.udp:getSrcPort()
	      local received = pkt.udp:getDstPort()
	      ipc.sendFdcFinAckMsg(pipes, flowId, received, now)
	   end
	   rxBufs:freeAll()
	   i = i + 1
	end -- ends while dpdk.running()
	txCtr:finalize()
	rxCtr:finalize()
end

return data1Mod
