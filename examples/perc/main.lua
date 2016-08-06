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

-- local PKT_SIZE	= 80
 -- 11B b/n control and host state, 6 b/n .. agg 80

function master(...)	 
   print("hello")
   --collectgarbage("stop")
   -- cores 1..7 part of CPU 1 in socket 1
	 -- port 0 is attached to socket 1
	 -- cores 8..16 part of CPU 2 in socket 2
	 -- port 1 is attached to socket 2
	 local numArgs = table.getn(arg)

	 local txDev = -1
	 local rxDev = -1

	 print("Got " .. numArgs .. " command-line arguments.")

	 local thisCore = dpdk.getCore()
	 local numCores = 8
	 local core1 = (thisCore + 1)%numCores
	 local core2 = (thisCore + 2)%numCores
	 local core3 = (thisCore + 3)%numCores
	 local core4 = (thisCore + 4)%numCores
	 local core5 = (thisCore + 5)%numCores
	 
	 local txPort = 0
	 txDev = device.config{ port = txPort, txQueues = 20, rxQueues = 4}
	 txDev:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 --assert(filter.DROP ~= nil)
	 txDev:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)
	 txDev:l2Filter(eth.TYPE_ACK, perc_constants.ACK_QUEUE)

	 assert(eth.TYPE_ACK ~= nil)
	 
	 local rxPort = 1
	 rxDev = device.config{ port = rxPort, txQueues = 20, rxQueues = 4}
	 rxDev:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_QUEUE)
	 rxDev:l2Filter(eth.TYPE_ACK, perc_constants.ACK_QUEUE)
	 rxDev:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)

	 numLinksUp = device.waitForLinks()

	 print("waiting for links")
	 if (numLinksUp == 2) then 
	    dpdk.setRuntime(1000)
	    print("all inks are up")
	    -- per-device pipes for app/control/data
	    --  communication
	    local pipesTxDev = ipc.getInterVmPipes()
	    local pipesRxDev = ipc.getInterVmPipes()
	    print("About to call monitor.getPerVmPipes({0, 1})")
	    local monitorPipes = monitor.getPerVmPipes({0, 1})
	    for pipeName, pipe in pairs(monitorPipes) do
	       print(pipeName)
	    end
	    
	    -- control and application on dev0, control on dev1
	    -- pipes to sync all participating threads
	    local readyPipes = ipc.getReadyPipes(6)
	    
	    local controlMonitorPipe = monitorPipes["control-0"]
	    assert(controlMonitorPipe ~= nil)
	    dpdk.launchLuaOnCore(
	       core1, "loadControlSlave", txDev,
	       pipesTxDev,
	       {["pipes"]= readyPipes, ["id"]=1},
	       controlMonitorPipe)
	    
	    dpdk.launchLuaOnCore(
	       core2, "loadControlSlave", rxDev,
	       pipesRxDev,
	       {["pipes"]= readyPipes, ["id"]=2},
	       nil)

	    local dataTxMonitorPipe = monitorPipes["data-0"]
	    dpdk.launchLuaOnCore(
	       core3, "loadDataSlave", txDev,
	       pipesTxDev,
	       {["pipes"]= readyPipes, ["id"]=3},
	       dataTxMonitorPipe)

	    dpdk.launchLuaOnCore(
	       core4, "loadDataSlave", rxDev,
	       pipesRxDev,
	       {["pipes"]= readyPipes, ["id"]=4})

	    dpdk.launchLuaOnCore(
	       core5, "loadMonitorSlave", monitorPipes,
	       {["pipes"]= readyPipes, ["id"]=5})

	    local appMonitorPipe = monitorPipes["app-0"]
	    assert(appMonitorPipe ~= nil)
	    assert(app2.applicationSlave ~= nil)
	    app2.applicationSlave(
	       pipesTxDev,
	       {["pipes"]= readyPipes, ["id"]=6},
	       appMonitorPipe)

	    dpdk.waitForFirstSlave({core1, core2, core3, core4})
	    --dpdk.waitForSlaves()
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










