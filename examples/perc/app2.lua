local ffi = require("ffi")
local dpdk	= require "dpdk"
local ipc = require "examples.perc.ipc"
local monitor = require "examples.perc.monitor"
local utils = require "utils"

app2Mod = {}
local PKT_PAYLOAD_SIZE = 1200
local MAX_FLOW_SIZE = 15000000 --15000000
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
   local active = {} -- app has started but not definitively ended yet
   --local workload = {1, -1, 1, 1, 1, -1, 1, -1}



   -- if lastFlowStarted is in active flows,
   -- and lastFlowEnded is no longer in active flows
   -- time to add/ remove another flow - add with prob (1 - current_flows/max_flows)
   
   local now = 0
   local nextSendTime = now --+ poissonDelay(MEAN_INTER_ARRIVAL_TIME)

   -- active flows is flows that have seen action in the last ACTIVE seconds
   -- we'll print out the FCT when a flow is GC-ed from active flows
   local numActiveFlows = 0
   local activeFlows = {}

   -- flowSize, startTime, committedPackets maintained for all flows (or all active flows?)
   -- TODO(lav): what to do about flowIds being re-used??
   local flowStartTime = {}
   local flowSize = {} -- of all flows
   local committedPacketsTime= {}
   local committedPacketsNumber= {}
   local lastActionTime = {} -- of all active flows
   
   while dpdk.running() do

      -- Get acks from PERC and update committed packets for all flows
      local msgs = ipc.fastAcceptMsgs(pipes, "fastPipeControlToAppFinAck", "pFcaFinAckMsg", 20)
      if next(msgs) ~= nil then
	 local now = dpdk.getTime()
	 for msgNo, msg in pairs(msgs) do
	    if flowSize[msg.flow] ~= nil then	       
	       local committedNumber = committedPacketsNumber[msg.flow]
	       if msg.size > committedNumber then
		  -- TODO(lav) V fails
		  -- assert(msg.endTime > committedPacketsTime[msg.flow])
		  committedPacketsNumber[msg.flow] = msg.size
		  committedPacketsTime[msg.flow] = msg.endTime
		  lastActionTime[msg.flow] = msg.endTime
	       end	    
	    end
	 end
      end

      -- Print FCT stats for stale flows and remove them from active list
      now = dpdk.getTime()
      for flowId, xx in pairs(activeFlows) do	 
	 -- TODO(lav): Flows with many packets could take a while
	 --  to hear back about 10% of the packets ..
	 if (now - lastActionTime[flowId] > 2) then
	    local lastCommitTime = committedPacketsTime[flowId]
	    local lastCommitNumber = committedPacketsNumber[flowId]
	    local startTime = flowStartTime[flowId]
	    local size = flowSize[flowId]
	    
	    local fct = lastCommitTime - startTime
	    local minFct = lastCommitNumber * (1.2e-6) 
	    print("Flow " .. flowId .. " kinda finished in "
		     .. fct .. "s (min : " .. minFct .. "s) "
		     .. "( " .. lastCommitNumber .. " / "
			.. size .. " )")
	    -- TODO(lav): V fails
	    assert(lastCommitNumber <= size)
	    local lossRate = (100*(size-lastCommitNumber))/size

	    if (monitorPipe ~= nil) then
	       monitorPipe:send(
		  ffi.new("genericMsg",
			  {["i1"]= flowId,
			     ["d1"]= fct*1e6,
			     ["d2"]= minFct*1e6,
			     ["i2"]= lossRate,
			     ["loop"]= size,
			     ["valid"]= 1234,
			     ["msgType"]= monitor.typeFlowFctLoss,
			     ["time"] = now
	       }))	       
	    end
	    
	    activeFlows[flowId] = nil
	    numActiveFlows = numActiveFlows - 1

	    
	    if (monitorPipe ~= nil) then
	       print("sending msg of typeAppActiveFlowsNum")
	       monitorPipe:send(
		  ffi.new("genericMsg",
			  {["i1"]= numActiveFlows,
			     ["valid"]= 1234,
			     ["msgType"]= monitor.typeAppActiveFlowsNum,
			     ["time"] = now
	       }))
	    end
	 end
      end

      -- Start new flows if it's time
      now = dpdk.getTime()
      if now > nextSendTime and numActiveFlows < 7 then
	 local size = getSize()
	 local numPackets = math.ceil(size / PKT_PAYLOAD_SIZE)
	 local sendTime = now
	 app2Mod.startNewFlow(newFlowId, numPackets, active, pipes, sendTime)
	 activeFlows[newFlowId] = sendTime
	 numActiveFlows = numActiveFlows + 1

	 flowStartTime[newFlowId] = sendTime
	 flowSize[newFlowId] = numPackets
	 committedPacketsNumber[newFlowId] = 0
	 committedPacketsTime[newFlowId] = 0
	 lastActionTime[newFlowId] = sendTime
	 
	 if monitorPipe ~= nil then
	    monitorPipe:send(
	       ffi.new("genericMsg",
		       {["i1"]= numActiveFlows,
			  ["valid"]= 1234,
			  ["msgType"]= monitor.typeAppActiveFlowsNum,
			  ["time"] = now
	    }))
	 end
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
	    assert(false)
	    print("wrapping flowid, starting at 100 again.")
	    newFlowId = 100
	 end
	 print("next send time is " .. nextSendTime)
      end
   end
end

return app2Mod
