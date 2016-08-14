local filter    = require "filter"
local dpdk	= require "dpdk"
local device	= require "device"
local pipe		= require "pipe"
local perc_constants = require "examples.perc.constants"
local monitor = require "examples.perc.monitor"
local ipc = require "examples.perc.ipc"
local app2 = require "examples.perc.app2"
local control2 = require "examples.perc.control2"
local data2 = require "examples.perc.data2"
local log = require "log"
local eth = require "proto.ethernet"
function master(txPort, rxPort)
	if not txPort or not rxPort then
	   return log:info("usage: txPort rxPort")
	end
	local txDev = device.config{port = txPort,
				    rxQueues = 4,
				    txQueues = perc_constants.MAX_QUEUES+1}
	local rxDev = device.config{port = rxPort,
				    rxQueues = 2,
				    txQueues = perc_constants.MAX_QUEUES+1}

	-- filters for data packets
	txDev:l2Filter(eth.TYPE_ACK, perc_constants.ACK_RXQUEUE)

	-- filters for control packets
	txDev:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_RXQUEUE)
	rxDev:l2Filter(eth.TYPE_PERCG, perc_constants.CONTROL_RXQUEUE)
	rxDev:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)
	txDev:l2Filter(eth.TYPE_DROP, perc_constants.DROP_QUEUE)


	dpdk.setRuntime(1000)
	local txIpcPipes = ipc.getInterVmPipes()
	local rxIpcPipes = ipc.getInterVmPipes()
	local monitorPipes = monitor.getPerVmPipes({txPort, rxPort})
	local readyPipes = ipc.getReadyPipes(6)
	
 	dpdk.launchLua("sendDataSlave", txDev, txIpcPipes, nil,
		     readyPipes, 1)
	dpdk.launchLua("controlSlave", txDev, txIpcPipes, nil,
		     readyPipes, 2)
	dpdk.launchLua("genFlowsSlave", txDev, txIpcPipes, nil,
		     readyPipes, 3)
	dpdk.launchLua("recvDataSlave", rxDev, nil, nil,
		     readyPipes, 4)
	dpdk.launchLua("controlSlave", rxDev, nil, nil,
		     readyPipes, 5)
	dpdk.launchLua("monitorSlave", monitorPipes, readyPipes, 6)
	dpdk.waitForSlaves()
end

function sendDataSlave(dev, ipcPipes, monitorPipes, readyPipes, id)
   local monitorPipe = nil
   if monitorPipes ~= nil then
      monitorPipe = monitorPipes["data-"..dev.id] end

   data2.txSlave(dev, ipcPipes, {["pipes"]=readyPipes, ["id"]=id},
		 monitorPipe)
end

function recvDataSlave(dev, ipcPipes, monitorPipes, readyPipes, id)
   data2.rxSlave(dev, {["pipes"]=readyPipes, ["id"]=id})

end

function controlSlave(dev, ipcPipes, monitorPipes, readyPipes, id)
   local monitorPipe = nil
   if monitorPipes ~= nil then
      monitorPipe = monitorPipes["control-"..dev.id] end

   control2.controlSlave(dev, ipcPipes,
			 {["pipes"]=readyPipes, ["id"]=id},
			 monitorPipe)
end   

function genFlowsSlave(dev, ipcPipes, monitorPipes, readyPipes, id)
   local monitorPipe = nil
   if monitorPipes ~= nil then
      monitorPipe = monitorPipes["app-".. dev.id] end

   app2.applicationSlave(ipcPipes,
			 {["pipes"]=readyPipes, ["id"]=id},
			 monitorPipe)
end

function monitorSlave(monitorPipes, readyPipes, id)
   monitor.monitorSlave(monitorPipes,
			{["pipes"]=readyPipes, ["id"]=id})

end
