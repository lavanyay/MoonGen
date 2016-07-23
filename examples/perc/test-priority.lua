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

-- RW DCB Transmit Descriptor Plane T1 Config
local RTTDT1C = 0x04908
local RTTDQSEL = 0x00004904
local PKT_SIZE	= 1124 -- without CRC

local ipc = require "examples.perc.ipc"
-- application thread: talks with control plane
-- thread via ipc functions sendFacStartMsg,
-- sendFacEndMsg(pipes, removeFlowId).
-- Receives completions and updates using
-- acceptMsgs(pipes, "slowPipeControlToApp")
--local app1 = require "examples.perc.app1"

-- perc control plane thread
--local control1 = require "examples.perc.control1"
-- perc data plane thread
--local data1 = require "examples.perc.data1"

-- local PKT_SIZE	= 80
 -- 11B b/n control and host state, 6 b/n .. agg 80

function master(...)	 
	 -- cores 1..7 part of CPU 1 in socket 1
	 -- port 0 is attached to socket 1
	 -- cores 8..16 part of CPU 2 in socket 2
	 -- port 1 is attached to socket 2
	 local numArgs = table.getn(arg)

	 print("Got " .. numArgs .. " command-line arguments.")

	 local thisCore = dpdk.getCore()
	 local numCores = 8
	 local core1 = (thisCore + 1)%numCores
	 local core2 = (thisCore + 2)%numCores

	 print("This core (rx) .. " .. thisCore
		  .. " core1 (high tx) .. " .. core1
		  .. " core2 (low tx) .. " .. core2)
	 
	 local txPort = 0
	 local txDev = device.config{ port = txPort, txQueues = 4}
	 
	 local rxPort = 1
	 local rxDev = device.config{ port = rxPort, rxQueues = 1}

	 numLinksUp = device.waitForLinks()

	 print("waiting for links")
	 if (numLinksUp == 2) then 
	    dpdk.setRuntime(1000)

	    -- per-device pipes for app/control/data
	    --  communication
	    --local pipesTxDev = ipc.getInterVmPipes()
	    --local pipesRxDev = ipc.getInterVmPipes() 

	    -- control and application on dev0, control on dev1
	    -- pipes to sync all participating threads
	    local readyPipes = ipc.getReadyPipes(2)
	    local highTag = 9999
	    local lowTag = 9998
	    
	    local highTxQueue = txDev:getTxQueue(0)
	    local lowTxQueue = txDev:getTxQueue(1)

	    highTxQueue:setRate(1000)
	    lowTxQueue:setRate(5000)

	    dpdk.sleepMillis(100)
	    
	    local highRxQueue = txDev:getRxQueue(0)
	    local lowRxQueue = txDev:getRxQueue(1)

	    dpdk.launchLuaOnCore(
	       core1, "loadTx", txDev,
	       highTxQueue, highTag,
	       {["pipes"]= readyPipes, ["id"]=1})

	    dpdk.launchLuaOnCore(
	       core2, "loadTx", txDev,
	       lowTxQueue, lowTag,
	       {["pipes"]= readyPipes, ["id"]=1})

 	    counterSlave(highRxQueue, 
	       {["pipes"]= readyPipes, ["id"]=2})
	    
	    dpdk.waitForSlaves()
	    else print("Not all devices are up")
	 end
end

function loadTx(txDev, queue, tag, readyInfo)
   local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = PKT_SIZE,
			ethSrc = queue,
			ethDst = "10:11:12:13:14:15",
			ip4Dst = "192.168.1.1",
			udpSrc = 1234,
			udpDst = tag
				       }
   end)
   bufs = mem:bufArray(128)
   local ctr = stats:newDevTxCounter( "UDP Dst " .. tag, txDev, "plain")

   ipc.waitTillReady(readyInfo)
	
   while dpdk.running() do
      bufs:alloc(PKT_SIZE)
      queue:send(bufs)
      ctr:update()
   end
   ctr:finalize()
end

function setTxPriorities(highQueue)
   local highPriority = 1.0

   dpdkc.write_reg32(
      highQueue.id, RTTDQSEL,
      highQueue.qid)

   dpdkc.write_reg32(
      highQueue.id, RTTDT1C,
      bit.band(math.floor(highPriority * 0x80), 0x3FF))
end

function addRxFilters(dev, tag1, queue1, tag2, queue2)
   -- tags/ src port in big endian
   filter1 = {[src_port]=tag1}
   filter2 = {[src_port]=tag2}
   dev:addHW5TupleFilter(filter1, queue1.qid)
   dev:addHW5TupleFilter(filter2, queue2.qid)
end

function counterSlave(queue, readyInfo)
	local bufs = memory.bufArray()
	local ctrs = {}

	ipc.waitTillReady(readyInfo)
	while dpdk.running() do
		local rx = queue:recv(bufs)
		for i = 1, rx do
			local buf = bufs[i]
			local pkt = buf:getUdpPacket()
			local port = pkt.udp:getDstPort()
			local ctr = ctrs[port]
			if not ctr then
				ctr = stats:newPktRxCounter("Port " .. port, "plain")
				ctrs[port] = ctr
			end
			ctr:countPacket(buf)
		end
		-- update() on rxPktCounters must be called to print statistics periodically
		-- this is not done in countPacket() for performance reasons (needs to check timestamps)
		for k, v in pairs(ctrs) do
			v:update()
		end
		bufs:freeAll()
	end
	for k, v in pairs(ctrs) do
		v:finalize()
	end
	-- TODO: check the queue's overflow counter to detect lost packets
end











