local ffi = require("ffi")
local pkt = require("packet")
local filter    = require "filter"
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

local ipc = require "examples.perc.ipc"
-- application thread: talks with control plane
-- thread via ipc functions sendFacStartMsg,
-- sendFacEndMsg(pipes, removeFlowId).
-- Receives completions and updates using
-- acceptMsgs(pipes, "slowPipeControlToApp")
local app1 = require "examples.perc.app1"
local app2 = require "examples.perc.app2"

-- perc control plane thread
local control1 = require "examples.perc.control2"
-- perc data plane thread
local data1 = require "examples.perc.data1"

-- local PKT_SIZE	= 80
 -- 11B b/n control and host state, 6 b/n .. agg 80

function master(...)	 
   --collectgarbage("stop")
   -- cores 1..7 part of CPU 1 in socket 1
	 -- port 0 is attached to socket 1
	 -- cores 8..16 part of CPU 2 in socket 2
	 -- port 1 is attached to socket 2
	 local numArgs = table.getn(arg)

	 local txDev = -1
	 local core1 = -1
	 local core2 = -1
	 local rxDev = -1

	 print("Got " .. numArgs .. " command-line arguments.")

	 local thisCore = dpdk.getCore()
	 local numCores = 8
	 core1 = (thisCore + 1)%numCores
	 core2 = (thisCore + 2)%numCores
	 core3 = (thisCore + 3)%numCores
	 
	 local txPort = 0
	 txDev = device.config{ port = txPort, txQueues = 20, rxQueues = 4}
	 txDev:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 --assert(filter.DROP ~= nil)
	 txDev:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)
	 txDev:l2Filter(eth.TYPE_FINACK, perc_constants.FINACK_QUEUE)
	 
	 local rxPort = 1
	 rxDev = device.config{ port = rxPort, txQueues = 20, rxQueues = 4}
	 rxDev:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 rxDev:l2Filter(eth.TYPE_FINACK, perc_constants.FINACK_QUEUE)
	 rxDev:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)

	 numLinksUp = device.waitForLinks()

	 print("waiting for links")
	 if (numLinksUp == 2) then 
	    dpdk.setRuntime(1000)

	    -- per-device pipes for app/control/data
	    --  communication
	    local pipesTxDev = ipc.getInterVmPipes()
	    local pipesRxDev = ipc.getInterVmPipes() 

	    -- control and application on dev0, control on dev1
	    -- pipes to sync all participating threads
	    local readyPipes = ipc.getReadyPipes(4)
	    

	    dpdk.launchLuaOnCore(
	       core1, "loadControlSlave", txDev,
	       pipesTxDev,
	       {["pipes"]= readyPipes, ["id"]=1})
	    
	    dpdk.launchLuaOnCore(
	       core2, "loadControlSlave", rxDev,
	       pipesRxDev,
	       {["pipes"]= readyPipes, ["id"]=2})

	    dpdk.launchLuaOnCore(
	       core3, "loadDataSlave", txDev,
	       pipesTxDev,
	       {["pipes"]= readyPipes, ["id"]=3})

	    app2.applicationSlave(
	       pipesTxDev,
	       {["pipes"]= readyPipes, ["id"]=4})

	    dpdk.waitForFirstSlave({core1, core2, core3})
	    --dpdk.waitForSlaves()
	    else print("Not all devices are up")
	 end
end

function loadControlSlave(dev, pipes, readyInfo)
   control1.controlSlave(dev, pipes, readyInfo)
end

function loadDataSlave(dev, pipes, readyInfo)
   data1.dataSlave(dev, pipes, readyInfo)
end










