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


function app1Mod.applicationSlave(pipes, readyInfo)
   local thisCore = dpdk.getCore()
   print("Running application slave on core " .. thisCore)   
   ipc.waitTillReady(readyInfo)
   local lastSentTime = dpdk.getTime()
   local newFlowId = 100
   local active = {}
   local interval = 1
   local workload = {1, -1, 1, 1, 1, -1, 1, -1}
   local seqNo = 1
   local numFlows = 0
   local activeFlows = {}
   local numActiveFlows = 0
   
   local now = 0
   while dpdk.running() do
      now = dpdk.getTime()

      local msgs = ipc.acceptMsgs(pipes, "slowPipeControlToApp")
      if next(msgs) ~= nil then
	 for msgNo, msg in pairs(msgs) do
	    print(msg["now"] .. ": " .. msg["msg"])
	    if string.find(msg["msg"], "rate") ~= nil then
	       local flow, rate
		  = msg["msg"]:match("updated rate of flow (%d+) to (%d+)")
	       assert(flow ~= nil)	       
	       if not activeFlows[flow] then
		  activeFlows[flow] = true
		  numActiveFlows = numActiveFlows + 1
	       end
	    else
	       local flow = msg["msg"]:match("control end flow (%d+)")
	       assert(flow ~= nil)	       
	       assert(activeFlows[flow] ~= nil)
	       activeFlows[flow] = nil
	       numActiveFlows = numActiveFlows - 1
	    end
	    print(" numActiveFlows: " .. numActiveFlows)
	 end
      end
      
      if dpdk.getTime() > lastSentTime + interval and workload[seqNo] ~= nil
      and numActiveFlows == numFlows then
	 local sendTime = dpdk.getTime()
	 numFlows = numFlows + workload[seqNo]
	 assert(numFlows >= 0)	 
	 if workload[seqNo] > 0 then
	    app1Mod.startNewFlow(newFlowId,active, pipes, sendTime)
	    print(sendTime .. ": add " .. newFlowId
		     .. ", new # flows: " .. numFlows .. "\n")
	    newFlowId = newFlowId+1
	 else
	    removeFlowId = app1Mod.endOldFlow(active, pipes)
	    print(sendTime .. ": remove " .. removeFlowId
		     .. ", new # flows: " .. numFlows .. "\n")

	 end
	 seqNo = seqNo + 1
	 lastSentTime = sendTime
      end
   end
end

return app1Mod
