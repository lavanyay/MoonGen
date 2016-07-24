local ffi = require("ffi")
local pkt = require("packet")

local filter    = require "filter"
local dpdkc	= require "dpdkc"
local dpdk	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local pipe		= require "pipe"
local ip4 = require "proto.ip4"
local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"
local pcap = require "pcap"

local ntoh16, hton16 = ntoh16, hton16

-- RW DCB Transmit Descriptor Plane T1 Config
local RTTDT1C = 0x04908
local RTTDQSEL = 0x00004904
local PKT_SIZE	= 4080 -- without CRC

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
	 local core3 = (thisCore + 3)%numCores
	 -- check same socket as port
	 
	 print("This core (rx) .. " .. thisCore
		  .. " core1 (high tx) .. " .. core1
		  .. " core2 (low tx) .. " .. core2
		  .. " core3 (low rx) .. " .. core3)
	 
	 local txPort = 0
	 local txDev = device.config{ port = txPort, txQueues = 4}
	 
	 local rxPort = 1
	 local rxDev = device.config{ port = rxPort, rxQueues = 2}

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
	    local readyPipes = ipc.getReadyPipes(3)
	    
	    local highTxQueue = txDev:getTxQueue(2)
	    local lowTxQueue = txDev:getTxQueue(3)

	    highTxQueue:setRate(9000)
	    lowTxQueue:setRate(3000)

	    --setTxPriorities(highTxQueue, lowTxQueue)
	    print("highTxQueue has rate " .. highTxQueue:getTxRate())
	    print("lowTxQueue has rate " .. lowTxQueue:getTxRate())
	    
	    local highRxQueue = rxDev:getRxQueue(0)
	    local lowRxQueue = rxDev:getRxQueue(1)
	    addRxFilters(rxDev, highRxQueue, lowRxQueue)

	    dpdk.sleepMillis(100)
	    dpdk.launchLuaOnCore(
	       core1, "loadTx", txDev,
	       highTxQueue, 0x1234,
	       {["pipes"]= readyPipes, ["id"]=1})

	    dpdk.launchLuaOnCore(
	       core2, "loadTx", txDev,
	       lowTxQueue, 0x1200,
	       {["pipes"]= readyPipes, ["id"]=2})

	    --dpdk.launchLuaOnCore(
	    --  core3, "counterSlave", lowRxQueue,
	    --  {["pipes"]= readyPipes, ["id"]=3})
	    
 	    counterSlave(lowRxQueue, 
	       {["pipes"]= readyPipes, ["id"]=3})
	    
	    dpdk.waitForSlaves()
	    else print("Not all devices are up")
	 end
end

function loadTx(txDev, queue, ethType, readyInfo)
   local mem = memory.createMemPool(function(buf)
	    buf:getEthernetPacket():fill{
	       ethType = ethType}
   end)
   bufs = mem:bufArray(128)
   --local ctr = stats:newDevTxCounter( "UDP Dst " .. tag, txDev, "plain")

   ipc.waitTillReady(readyInfo)
	
   while dpdk.running() do
      bufs:alloc(PKT_SIZE)
      queue:send(bufs)
      --ctr:update()
   end
   --ctr:finalize()
end

function setTxPriorities(highQueue, lowQueue)
   local highPriority = 1.0
   local lowPriority = 0
   
   dpdkc.write_reg32(
      highQueue.id, RTTDQSEL,
      highQueue.qid)

   dpdkc.write_reg32(
     highQueue.id, RTTDT1C, --0x3FF)
      bit.band(math.floor(highPriority * 0x80), 0x3FF))

   dpdkc.write_reg32(
      lowQueue.id, RTTDQSEL,
      lowQueue.qid)

   dpdkc.write_reg32(
      lowQueue.id, RTTDT1C, --0x000)
      bit.band(math.floor(lowPriority * 0x80), 0x3FF))

end

function addRxFilters(dev, highQueue, lowQueue)
   dev:flushHWFilter()
   dpdk.sleepMillis(1000)
   print("adding filter for " .. tostring(0x1234)
	    .. " to enqueue on " .. tostring(highQueue.qid))
   print("adding filter for " .. tostring(0x1200)
	    .. " to enqueue on " .. tostring(lowQueue.qid))
   dev:l2Filter(0x1234, highQueue.qid)
   dev:l2Filter(0x1200, lowQueue.qid)
   
   --dev:addHWEthertypeFilter({["ether_type"]=hton16(0x1234)},
   --   lowQueue.qid)
   --dev:addHWEthertypeFilter({["ether_type"]=hton16(0x1200)},
   --  lowQueue.qid)
   --dev:addHWEthertypeFilter({["ether_type"]=hton16(0x12006)},
   --  lowQueue.qid)
end

function counterSlave(queue, readyInfo)
	local bufs = memory.bufArray()
	local ctrs = {}

	ipc.waitTillReady(readyInfo)
	print("starting counter")
	while dpdk.running() do
		local rx = queue:recv(bufs)
		for i = 1, rx do
			local buf = bufs[i]
			local pkt = buf:getEthernetPacket()
			local ethType = pkt.eth:getType()
			local ctr = ctrs[ethType]
			if not ctr then
			   ctr = stats:newPktRxCounter(
			      "RxQueue " .. queue.qid
				 .. ", ethType " .. ethType, "plain")
				ctrs[ethType] = ctr
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











