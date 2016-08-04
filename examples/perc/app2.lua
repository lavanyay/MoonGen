local ffi = require("ffi")
local dpdk	= require "dpdk"
local ipc = require "examples.perc.ipc"
local monitor = require "examples.perc.monitor"
local utils = require "utils"

app2Mod = {}
local PKT_PAYLOAD_SIZE = 1200
local MAX_FLOW_SIZE = 15000000
local MEAN_INTER_ARRIVAL_TIME = 1

-- app generates workload with poisson arrival and random size distribution (for now)
function app2Mod.startNewFlow(newFlowId, numPackets, active, pipes, now)
   table.insert(active, newFlowId)

   local destination = 2
   assert(newFlowId >= 100)
   ipc.sendFacStartMsg(pipes, newFlowId, destination, numPackets)
end

--function app2Mod.endOldFlow(active, pipes)
--   local removeFlowId = table.remove(active)
--   ipc.sendFacEndMsg(pipes, removeFlowId)
--   return removeFlowId
--end

-- in main loop

function getSize()
   return (math.random() * MAX_FLOW_SIZE)
end

function app2Mod.applicationSlave(pipes, readyInfo, monitorPipe)
   local thisCore = dpdk.getCore()
   print("Running application slave on core " .. thisCore)   
   ipc.waitTillReady(readyInfo)
   local lastSentTime = dpdk.getTime()
   local newFlowId = 100
   local active = {} -- app has started but not ended yet
   --local workload = {1, -1, 1, 1, 1, -1, 1, -1}
   local numActiveFlows = 0


   -- if lastFlowStarted is in active flows,
   -- and lastFlowEnded is no longer in active flows
   -- time to add/ remove another flow - add with prob (1 - current_flows/max_flows)
   
   local now = 0
   local nextSendTime = now --+ poissonDelay(MEAN_INTER_ARRIVAL_TIME)
   local activeFlows = {}
   local flowSize = {} -- of active flows

   local hopelessFlows = {}
   while dpdk.running() do
      local msgs = ipc.fastAcceptMsgs(pipes, "fastPipeControlToAppFinAck", "pFcaFinAckMsg", 20)
      if next(msgs) ~= nil then
	 for msgNo, msg in pairs(msgs) do
	    if (activeFlows[msg.flow] ~= nil) then
	       local fct = msg.endTime - activeFlows[msg.flow]
	       local minFct = msg.size * (1.2e-6) 
	       print("Flow " .. msg.flow .. " finished (FIN-ACK) in " .. fct
			.. "s (min : " .. minFct .. "s) , received "
			.. msg.size .. " of " .. flowSize[msg.flow]
			.. " packets.")
	       activeFlows[msg.flow] = nil
	       flowSize[msg.flow] = nil
	       numActiveFlows = numActiveFlows - 1
	       assert(monitorPipe ~= nil)
	       print("sending msg of typeAppActiveFlowsNum")
	       monitorPipe:send(
		  ffi.new("genericMsg",
			  {["i1"]= numActiveFlows,
			     ["valid"]= 1234,
			     ["msgType"]= monitor.typeAppActiveFlowsNum}))
			     
	    elseif (hopelessFlows[msg.flow] ~= nil) then
	       local fct = msg.endTime - hopelessFlows[msg.flow].startTime
	       local minFct = msg.size * (1.2e-6) 
	       print("Flow " .. msg.flow .. " finished (FIN-ACK) in " .. fct
			.. "s (min : " .. minFct .. "s) , received "
			.. msg.size .. " of " .. hopelessFlows[msg.flow].flowSize
			.. " packets.")

	    else
	       print("Don't know what to do with FinAck for flow " .. msg.flow)
	    end
	 end
      end

      local gcnow = dpdk.getTime()
      for flow, startTime in pairs(activeFlows) do
	 if (gcnow - startTime > 5) then
	    print("Flow " .. flow .. " is taking > 5s since start. Remove.")
	    hopelessFlows[flow] = {["startTime"] = activeFlows[flow], ["size"] = flowSize[flow]}
	    activeFlows[flow] = nil
	    flowSize[flow] = nil	    
	    numActiveFlows = numActiveFlows - 1
	 end
      end
      
      now = dpdk.getTime()
      if now > nextSendTime and numActiveFlows < 7 then
	 local size = getSize()
	 local numPackets = math.ceil(size / PKT_PAYLOAD_SIZE)
	 local sendTime = now
	 app2Mod.startNewFlow(newFlowId, numPackets, active, pipes, sendTime)
	 activeFlows[newFlowId] = sendTime
	 flowSize[newFlowId] = numPackets
	 numActiveFlows = numActiveFlows + 1
	 nextSendTime = sendTime + poissonDelay(MEAN_INTER_ARRIVAL_TIME)
	 local tries = 0
	 while (nextSendTime - sendTime > 5) do
	    nextSendTime = sendTime + poissonDelay(MEAN_INTER_ARRIVAL_TIME)
	    tries = tries + 1
	    assert(tries < 50)
	 end
	 print("Memory in use " .. collectgarbage("count") .. "Kb")
	 print("Change  at "
		  .. sendTime .. ": add " .. newFlowId .. " of size " .. size
		  .. "B, so " .. numActiveFlows .. " active flows"
		  .. ", next sendTime in " .. (nextSendTime - now) .. "s.\n")

	 newFlowId = newFlowId+1
	 if (newFlowId == 256) then
	    print("wrapping flowid, starting at 100 again.")
	    newFlowId = 100
	 end
	 print("next send time is " .. nextSendTime)
      end
   end
end

return app2Mod
