local ffi = require("ffi")
local pipe		= require "pipe"

ipcMod = {}

ffi.cdef[[
typedef struct { int flow, destination, size; double startTime;} facStartMsg;  
typedef struct { int flow, destination, size, queue; } fcdStartMsg;  
typedef struct { int flow; } facEndMsg;  
typedef struct { int flow; double endTime;} fdcEndMsg;  
typedef facStartMsg* pFacStartMsg;
typedef fcdStartMsg* pFcdStartMsg;
typedef facEndMsg* pFacEndMsg;
typedef fdcEndMsg* pFdcEndMsg;
// Declare a struct and typedef.
]]


function ipcMod.sendFacStartMsg(pipes, flow, destination, size, startTime)
   local msg = ffi.new("facStartMsg[?]", 1)
   msg[0].flow = flow
   msg[0].destination = destination
   msg[0].size = size
   msg[0].startTime = startTime
   ipcMod.sendMsgs(pipes, "fastPipeAppToControlStart", msg)
   --return msg
end

function ipcMod.sendFcdStartMsg(pipes, flow, destination, size, queue)
   local msg = ffi.new("fcdStartMsg[?]", 1)
   msg[0].flow = flow
   msg[0].destination = destination
   msg[0].size = size
   msg[0].queue = queue
   ipcMod.sendMsgs(pipes, "fastPipeControlToDataStart", msg)
   --return msg
end

function ipcMod.sendFacEndMsg(pipes, flow)
   local msg = ffi.new("facEndMsg[?]", 1)
   msg[0].flow = flow
   ipcMod.sendMsgs(pipes, "fastPipeAppToControlEnd", msg)
   --return msg
end

function ipcMod.sendFdcEndMsg(pipes, flow, endTime)
   local msg = ffi.new("fdcEndMsg[?]", 1)
   msg[0].flow = flow
   msg[0].endTime = endTime
   ipcMod.sendMsgs(pipes, "fastPipeDataToControlEnd", msg)
   --return msg
end

function ipcMod.acceptFacStartMsgs(pipes)
   return ipcMod.acceptMsgs(pipes, "fastPipeAppToControlStart", "pFacStartMsg")
end

function ipcMod.acceptFcdStartMsgs(pipes)
   return ipcMod.acceptMsgs(pipes, "fastPipeControlToDataStart", "pFcdStartMsg")
end

function ipcMod.acceptFacEndMsgs(pipes)
   return ipcMod.acceptMsgs(pipes, "fastPipeAppToControlEnd", "pFacEndMsg")
end

function ipcMod.acceptFdcEndMsgs(pipes)
   return ipcMod.acceptMsgs(pipes, "fastPipeDataToControlEnd", "pFdcEndMsg")
end


function ipcMod.sendMsgs(pipes, pipeName, msg)	 
	 -- update send time for this pipe in msg.flowEvent.
	 -- and can turn off logging
   pipes[pipeName]:send(msg)
end

function ipcMod.acceptMsgs(pipes, pipeName, msgType)
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

function ipcMod.getInterVmPipes()
   -- controlToData: to start flow
   -- dataToControl: end of data
   -- appToControl: to start flow
   -- appToData: to end flow
   -- slowPipe ApplicationSlave: (t, start/ change rate/ end of data/ end of control) 
	 local pipes =  {
	 	 ["fastPipeAppToControlStart"] = pipe.newFastPipe(),
	 	 ["fastPipeAppToControlEnd"] = pipe.newFastPipe(),
	 	 ["fastPipeDataToControlEnd"] = pipe.newFastPipe(),
		 ["slowPipeControlToApp"] = pipe.newSlowPipe(), 
		 ["fastPipeControlToDataStart"] = pipe.newFastPipe() 
	 }

	 return pipes
end

function ipcMod.getReadyPipes(numParticipants)
	 -- Setup pipes that slaves use to figure out when all are ready
	 local readyPipes = {}
	 local i = 1
	 while i <= numParticipants do
	       readyPipes[i] = pipe.newSlowPipe()
	       i = i + 1
	       end
	 return readyPipes
end

function ipcMod.waitTillReady(readyInfo)
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
function ipcMod.printFlowEvent(flowEvent) 
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

return ipcMod
