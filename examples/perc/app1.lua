local dpdk	= require "dpdk"
local ipc = require "examples.perc.ipc"

app1Mod = {}
function app1Mod.startNewFlow(newFlowId, active, pipes, now)
   table.insert(active, newFlowId)
   ipc.sendFacStartMsg(pipes, newFlowId, 2, now)
end

function app1Mod.endOldFlow(active, pipes)
   local removeFlowId = table.remove(active)
   ipc.sendFacEndMsg(pipes, removeFlowId)
   return removeFlowId
end

-- in main loop
-- get flow completions and update set of active flows
-- make a change, wait for control rates to converge
-- repeat
-- up to 1000 changes
-- see how long to converge? .. step 1

-- or just start or remove flow

-- poisson workload
-- but we need to send data packets to get real FCTs
-- maybe just do that.. step 2

-- get queue size and link usage from NICs .. step XX

function app1Mod.applicationSlave(pipes, readyInfo)
   local thisCore = dpdk.getCore()
   print("Running application slave on core " .. thisCore)   
   ipc.waitTillReady(readyInfo)
   local lastSentTime = dpdk.getTime()
   local newFlowId = 100
   local active = {} -- app has started but not ended yet

   --local workload = {1, -1, 1, 1, 1, -1, 1, -1}
   local seqNo = 1
   local numFlows = 0
   local maxFlows = 3
   local activeFlows = {} -- control thread has updated rate but not started end yet
   local numActiveFlows = 0

   local lastFlowStarted = nil
   local lastFlowEnded = nil

   -- if lastFlowStarted is in active flows,
   -- and lastFlowEnded is no longer in active flows
   -- time to add/ remove another flow - add with prob (1 - current_flows/max_flows)
   
   local changeNo = 1
   local now = 0
   while dpdk.running() do
      now = dpdk.getTime()

      local msgs = ipc.acceptMsgs(pipes, "slowPipeControlToApp")
      if next(msgs) ~= nil then
	 for msgNo, msg in pairs(msgs) do
	    print(msg["now"] .. ": " .. msg["msg"])
	    if string.find(msg["msg"], "rate") ~= nil then
	       local flow
		  = msg["msg"]:match("updated rate of flow (%d+) to")
	       assert(flow ~= nil)
	       flow = tonumber(flow)
	       if not activeFlows[flow] then
		  activeFlows[flow] = true
		  print("Added " .. flow
			   .. " to active flows, "
			   .. " last flow that started was "
			   .. lastFlowStarted)
		  numActiveFlows = numActiveFlows + 1
	       end
	    else
	       local flow = msg["msg"]:match("control end flow (%d+)")
	       assert(flow ~= nil)
	       flow = tonumber(flow)
	       assert(activeFlows[flow] ~= nil)
	       activeFlows[flow] = nil
	       numActiveFlows = numActiveFlows - 1
	       print("Removed " .. flow
			.. " from active flows, "
			.. " last flow that started was "
			.. lastFlowEnded)

	    end
	    print(" numActiveFlows: " .. numActiveFlows)
	 end
      end
      
      if dpdk.getTime() > lastSentTime
	 and (lastFlowStarted == nil
		 or
		 (activeFlows[lastFlowStarted] == true
		     and lastFlowStarted ~= lastFlowEnded)
		 or
		 (activeFlows[lastFlowStarted] == nil
		     and lastFlowStarted == lastFlowEnded))
	 and (lastFlowEnded == nil
		 or activeFlows[lastFlowEnded] == nil)
      then
	 local sendTime = dpdk.getTime()
	 
	 local numRequestsNotCompleted = 0
	 for k, v in active do
	    numRequestsNotCompleted = numRequestNotCompleted + 1
	 end
	 assert(numActiveFlows <= numRequestsNotCompleted)
	 local threshold = ((1.0*numRequestsNotCompleted)/maxFlows)
	 
	 if math.random() <  threshold and threshold <= 1 then
	    removeFlowId = app1Mod.endOldFlow(active, pipes)
	    lastFlowEnded = removeFlowId
	    print("Change " .. seqNo .. " at "
		     .. sendTime .. ": remove " .. removeFlowId .. "\n")
	 elseif numActiveFlows < maxFlows and newFlowId < 200 then
	    app1Mod.startNewFlow(newFlowId,active, pipes, sendTime)
	    lastFlowStarted = newFlowId
	    print("Change " .. seqNo .. " at "
		     .. sendTime .. ": add " .. newFlowId
		  .. "\n")
	    newFlowId = newFlowId+1
	 else
	    
	 end
	 seqNo = seqNo + 1
	 lastSentTime = sendTime
      end
   end
end

return app1Mod
