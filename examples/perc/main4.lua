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
local monitor = require "examples.perc.monitor"
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

function master(...)	 
   print("hello")
   --collectgarbage("stop")
   -- cores 1..7 part of CPU 1 in socket 1
	 -- port 0 is attached to socket 1
	 -- cores 8..16 part of CPU 2 in socket 2
	 -- port 1 is attached to socket 2
	 local numArgs = table.getn(arg)

	 local port0 = 0
	 local port1 = 1
	 local port2 = 2
	 local port3 = 3
	 
	 local txDev = nil
	 local rxDev1 = nil
	 local rxDev2 = nil
	 local rxDev3 = nil
	 
	 print("Got " .. numArgs .. " command-line arguments.")

	 local thisCore = dpdk.getCore()
	 local numCores = 8
	 local core1 = (thisCore + 1)%numCores
	 local core2 = (thisCore + 2)%numCores
	 local core3 = (thisCore + 3)%numCores
	 local core4 = (thisCore + 4)%numCores
	 local core5 = (thisCore + 5)%numCores
	 local core6 = (thisCore + 6)%numCores
	 local core7 = (thisCore + 7)%numCores
	 local core8 = (thisCore + 8)%numCores
	 
	 txDev = device.config{ port = port0, txQueues = 20, rxQueues = 4}
	 txDev:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 --assert(filter.DROP ~= nil)
	 txDev:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)
	 txDev:l2Filter(eth.TYPE_ACK, perc_constants.ACK_QUEUE)

	 assert(eth.TYPE_ACK ~= nil)
	 

	 rxDev1 = device.config{ port = port1, txQueues = 20, rxQueues = 4}
	 rxDev1:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 rxDev1:l2Filter(eth.TYPE_ACK, perc_constants.ACK_QUEUE)
	 rxDev1:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)

	 rxDev2 = device.config{ port = port2, txQueues = 20, rxQueues = 4}
	 rxDev2:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 rxDev2:l2Filter(eth.TYPE_ACK, perc_constants.ACK_QUEUE)
	 rxDev2:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)

	 rxDev3 = device.config{ port = port3, txQueues = 20, rxQueues = 4}
	 rxDev3:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 rxDev3:l2Filter(eth.TYPE_ACK, perc_constants.ACK_QUEUE)
	 rxDev3:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)


	 local numLinksUp = device.waitForLinks()

	 print("waiting for links")
	 if (numLinksUp == 4) then 
	    dpdk.setRuntime(1000)
	    print("all 4 links are up")
	    -- per-device pipes for app/control/data
	    --  communication
	    local pipesDev0 = ipc.getInterVmPipes()
	    local pipesDev1 = ipc.getInterVmPipes()
	    local pipesDev2 = ipc.getInterVmPipes()
	    local pipesDev3 = ipc.getInterVmPipes()
	    
	    print("About to call monitor.getPerVmPipes({0, 1})")
	    local monitorPipes = monitor.getPerVmPipes({0, 1})
	    for pipeName, pipe in pairs(monitorPipes) do
	       print(pipeName)
	    end
	    
	    -- control and application on dev0, control on dev1
	    -- pipes to sync all participating threads
	    local readyPipes = ipc.getReadyPipes(5)
	    
	    local controlMonitorPipe = monitorPipes["control-0"]
	    assert(controlMonitorPipe ~= nil)
	    dpdk.launchLuaOnCore(
	       core4, "loadControlSlave", txDev,
	       pipesDev0,
	       {["pipes"]= readyPipes, ["id"]=4},
	       nil)
	    
	    dpdk.launchLuaOnCore(
	       core1, "loadControlSlave", rxDev1,
	       pipesDev1,
	       {["pipes"]= readyPipes, ["id"]=1},
	       nil)

	    dpdk.launchLuaOnCore(
	       core2, "loadControlSlave", rxDev2,
	       pipesDev2,
	       {["pipes"]= readyPipes, ["id"]=2},
	       nil)

	    dpdk.launchLuaOnCore(
	       core3, "loadControlSlave", rxDev2,
	       pipesDev3,
	       {["pipes"]= readyPipes, ["id"]=3},
	       nil)

	    -- local dataTxMonitorPipe = monitorPipes["data-0"]
	    -- dpdk.launchLuaOnCore(
	    --    core3, "loadDataSlave", txDev,
	    --    pipesDev0,
	    --    {["pipes"]= readyPipes, ["id"]=3},
	    --    dataTxMonitorPipe)

	    -- dpdk.launchLuaOnCore(
	    --    core4, "loadDataSlave", rxDev1,
	    --    pipesDev1,
	    --    {["pipes"]= readyPipes, ["id"]=4})

	    -- dpdk.launchLuaOnCore(
	    --    core5, "loadMonitorSlave", monitorPipes,
	    --    {["pipes"]= readyPipes, ["id"]=5})

	    -- local appMonitorPipe = monitorPipes["app-0"]
	    -- assert(appMonitorPipe ~= nil)
	    assert(app2.applicationSlave ~= nil)
	    app2.applicationSlave(
	        pipesDev0,
	        {["pipes"]= readyPipes, ["id"]=5},
	        nil)

	    --dpdk.waitForFirstSlave({core1, core2, core3, core4})
	    dpdk.waitForSlaves()
	    else print("Not all devices are up")
	 end
end

function loadControlSlave(dev, pipes, readyInfo, monitorPipe)
   control1.controlSlave(dev, pipes, readyInfo, monitorPipe)
end

function loadDataSlave(dev, pipes, readyInfo, monitorPipe)
   data1.dataSlave(dev, pipes, readyInfo, monitorPipe)
end

function loadMonitorSlave(monitorPipes, readyInfo)
   monitor.monitorSlave(monitorPipes, readyInfo)
end










