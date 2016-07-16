local ffi = require("ffi")
local pipe		= require "pipe"

mod = {}

ffi.cdef[[
typedef struct { int flow, destination; } facStartMsg;  
typedef struct { int flow, destination, queue; } fcdStartMsg;  
typedef struct { int flow; } facEndMsg;  
typedef facStartMsg* pFacStartMsg;
typedef fcdStartMsg* pFcdStartMsg;
typedef facEndMsg* pFacEndMsg;
// Declare a struct and typedef.
]]


function mod.sendFacStartMsg(pipes, flow, destination)
   local msg = ffi.new("facStartMsg[?]", 1)
   msg[0].flow = flow
   msg[0].destination = destination

   mod.sendMsgs(pipes, "fastPipeAppToControlStart", msg)
   --return msg
end

function mod.sendFcdStartMsg(pipes, flow, destination, queue)
   local msg = ffi.new("fcdStartMsg[?]", 1)
   msg[0].flow = flow
   msg[0].destination = destination
   msg[0].queue = queue
   mod.sendMsgs(pipes, "fastPipeControlToDataStart", msg)
   --return msg
end

function mod.sendFacEndMsg(pipes, flow)
   local msg = ffi.new("facEndMsg[?]", 1)
   msg[0].flow = flow
   mod.sendMsgs(pipes, "fastPipeAppToControlEnd", msg)
   --return msg
end

function mod.acceptFacStartMsgs(pipes)
   return mod.acceptMsgs(pipes, "fastPipeAppToControlStart", "pFacStartMsg")
end

function mod.acceptFcdStartMsgs(pipes)
   return mod.acceptMsgs(pipes, "fastPipeControlToDataStart", "pFcdStartMsg")
end

function mod.acceptFacEndMsgs(pipes)
   return mod.acceptMsgs(pipes, "fastPipeAppToControlEnd", "pFacEndMsg")
end


function mod.sendMsgs(pipes, pipeName, msg)	 
	 -- update send time for this pipe in msg.flowEvent.
	 -- and can turn off logging
   pipes[pipeName]:send(msg)
end

function mod.acceptMsgs(pipes, pipeName, msgType)
   if pipes == nil or pipes[pipeName] == nil then
      print("acceptMsgs on nil pipe! return!!")
      return
   end 

   local pipe = pipes[pipeName]
   local numMsgs = pipe:count()
   if numMsgs ~= 0 then
      print(tostring(numMsgs) .. " msgs on pipe " .. pipeName)	
   end
   local msgs = {}
   while numMsgs > 0 do
      local msg = pipe:recv()
      if msgType ~= nil then
	 msg = ffi.cast(msgType, msg)
      end
      msgs[numMsgs] = msg
      print("Got msg # " .. tostring(numMsgs) .. " for flow " .. tostring(msg.flow) .. " on pipe " .. pipeName)
      numMsgs = numMsgs - 1
   end
   return msgs
end	 

function mod.getInterVmPipes()
   -- controlToData: to start flow
   -- dataToControl: end of data
   -- appToControl: to start flow
   -- appToData: to end flow
   -- slowPipe ApplicationSlave: (t, start/ change rate/ end of data/ end of control) 
	 local pipes =  {
	 	 ["fastPipeAppToControlStart"] = pipe.newFastPipe(),
	 	 ["fastPipeAppToControlEnd"] = pipe.newFastPipe(),
		 ["slowPipeControlToApp"] = pipe.newSlowPipe(), 
		 ["fastPipeControlToDataStart"] = pipe.newFastPipe() 
	 }

	 return pipes
end

function mod.getReadyPipes(numParticipants)
	 -- Setup pipes that slaves use to figure out when all are ready
	 local readyPipes = {}
	 local i = 1
	 while i <= numParticipants do
	       readyPipes[i] = pipe.newSlowPipe()
	       i = i + 1
	       end
	 return readyPipes
end

function mod.waitTillReady(readyInfo)
	 -- tell others we're ready and check if others are ready
	 local myPipe = readyInfo.pipes[readyInfo.id]
	 if myPipe ~= nil then	 	 
	    	 -- tell others I'm ready  
	 	 for pipeNum,pipe in ipairs(readyInfo.pipes) do
	 	     if pipeNum ~= readyInfo.id then 
	 	     	pipe:send({["1"]=pipeNum})
	 	 	end
	 	     pipeNum = pipeNum + 1
	 	 end
	
		 local numPipes = table.getn(readyInfo.pipes)

		 -- busy wait till others are ready
	 	 local numReadyMsgs = 0	 
	 	 while numReadyMsgs < numPipes-1 do
	 	       if myPipe:recv() ~= nil then 
	 	       	  numReadyMsgs = numReadyMsgs + 1
	 	 	  end
	 	       end

	 	 print("Received " .. numReadyMsgs .. " ready messages on pipe # " .. readyInfo.id)
		 end
end

-- prints times when msg was put on different queues and FCT
function mod.printFlowEvent(flowEvent) 
     local eventsByName = flowEvent
     local eventsByTime = {}
     local times = {}		     

     for pipeName, times in pairs(flowEvent) do
     	 local waitTime
     	 if times.accept ~= nil and times.send ~= nil then
	    waitTime = times.accept - times.send
	    else waitTime = nil
	    end
     	 --print(tostring(pipeName) .. ": sent at " .. tostring(times.send) .. " ms, waited for " .. tostring(waitTime) .. " ms.")
	 end

     if flowEvent.appToControl.send ~= nil
     and flowEvent.dataToApp.accept ~= nil then
     	local fct = flowEvent.dataToApp.accept - flowEvent.appToControl.send
     	print("FlowCompletionTime .. " .. tostring(fct) .. " ms")
	print("StartTime .. " .. tostring(flowEvent.appToControl.send*1000) .. " us")
	end
end

return mod
