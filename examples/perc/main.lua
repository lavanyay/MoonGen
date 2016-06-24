local ffi = require("ffi")
local pkt = require("packet")

local dpdk	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local pipe		= require "pipe"
local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"
local pcap = require "pcap"

local Link = require "examples.perc.perc_link"
local EndHost = require "examples.perc.end_host"


local PKT_SIZE	= 80
 -- 11B b/n control and host state, 6 b/n .. agg 80

function master(...)	 
	 -- cores 1..7 part of CPU 1 in socket 1
	 -- port 0 is attached to socket 1
	 -- cores 8..16 part of CPU 2 in socket 2
	 -- port 1 is attached to socket 2
	 local numArgs = table.getn(arg)

	 local txDev = -1
	 local core1 = -1
	 local core2 = -1
	 local core3 = -1
	 local rxDev = -1
	 local core4 = -1

	 print("Got " .. numArgs .. " command-line arguments.")

	 local thisCore = dpdk.getCore()
	 local numCores = 8
	 core1 = (thisCore + 1)%numCores
	 core2 = (thisCore + 2)%numCores

	 
	 local txPort = 0
	 txDev = device.config{ port = txPort, txQueues = 20}
	 
	 local rxPort = 1
	 rxDev = device.config{ port = rxPort, rxQueues = 20}

	 numLinksUp = device.waitForLinks()

	 print("waiting for links")
	 if (numLinksUp == 2) then 
	    dpdk.setRuntime(1000)

	    local pipesTxDev = getInterVmPipes()
	    local pipesRxDev = getInterVmPipes() 
	    local readyPipes = getReadyPipes(3) -- control and application on dev0, control on dev1

	    dpdk.launchLuaOnCore(core1, "loadControlSlave", txDev, pipesTxDev, {["pipes"]= readyPipes, ["id"]=1})
	    dpdk.launchLuaOnCore(core2, "loadControlSlave", rxDev, pipesRxDev, {["pipes"]= readyPipes, ["id"]=2})

	    loadApplicationSlave2(pipesTxDev, {["pipes"]= readyPipes, ["id"]=3})
	    dpdk.waitForSlaves()
	    else print("Not all devices are up")
	 end
end

function getInterVmPipes()
	 local pipes =  {
	 	 ["pipeFlowStart"] = pipe.newSlowPipe(),
	 	 ["pipeFlowCompletions1"] = pipe.newSlowPipe(),
		 ["pipeFlowCompletions2"] = pipe.newSlowPipe(),
		 ["pipeFlowStartData"] = pipe.newSlowPipe()
	 }

	 return pipes
end

function getReadyPipes(numParticipants)
	 -- Setup pipes that slaves use to figure out when all are ready
	 local readyPipes = {}
	 local i = 1
	 while i <= numParticipants do
	       readyPipes[i] = pipe.newSlowPipe()
	       i = i + 1
	       end
	 return readyPipes
end

function waitTillReady(readyInfo)
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

function loadApplicationSlave2(pipes, readyInfo)
   local thisCore = dpdk.getCore()
   print("Running application slave on core " .. thisCore)
   
   waitTillReady(readyInfo)

         local lastSentTime = dpdk.getTime()

	 local newFlowId = 100

	 local active = {}
	 local answer
	 local done = false
	 while dpdk.running() and done == false do
	 
	  if dpdk.getTime() > lastSentTime + 1 then
	   io.write("start a new flow (y/n)? ")
	   io.flush()
	   answer=io.read()
           if answer == "y" then
	      print("Starting new flow " .. newFlowId)
	      table.insert(active, newFlowId)
	      local nextFlowMsg = {["flow"] = tostring(newFlowId), ["destination"]="3",
	      		       	   ["flowEvent"] = {}}
	      sendMsgs(pipes, "pipeFlowStart", nextFlowMsg)
	      lastSentTime = dpdk.getTime()
	      newFlowId = newFlowId + 1
	      elseif answer == "n" then
               local removeFlowId = table.remove(active)
	       print("Removing flow " .. removeFlowId)
	       local stopFlowMsg = {["flow"] = tostring(removeFlowId)}
	       sendMsgs(pipes, "pipeFlowCompletions1", stopFlowMsg)
	       lastSentTime = dpdk.getTime()
	      elseif answer == "quit" then
	       done = true
	   end
	  end
	 end

end


-- prints times when msg was put on different queues and FCT
function printFlowEvent(flowEvent) 
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

     if flowEvent.pipeFlowStart.send ~= nil and flowEvent.pipeFlowCompletions2.accept ~= nil then
     	local fct = flowEvent.pipeFlowCompletions2.accept - flowEvent.pipeFlowStart.send
     	print("FlowCompletionTime .. " .. tostring(fct) .. " ms")
	print("StartTime .. " .. tostring(flowEvent.pipeFlowStart.send*1000) .. " us")
	end
end


-- handles flow start messages from applications - to send first control, assign a free queue for data
-- handles flow completion message from "data slave", sends exit packet to free up bandwidth, reclaims queue
-- receives control packets on rx queue, computes new bottleneck info and sends out new packets
-- adjusts rates of data queues based on rxd control packets

function loadControlSlave(dev, pipes, readyInfo)
      local thisCore = dpdk.getCore()
      print("Running control slave on core " .. thisCore)

	-- create memory pool to be used by control packets we'll tx
	-- default values are most common values
	-- TODO(lav): ethSrc is source's MAC address (port 0/ ensf0) 
	--  and ethDst is ..
	local mem = memory.createMemPool(function(buf)
		buf:getPercc1Packet():fill{
			pktLength = PKT_SIZE,
			percgSource = readyInfo.id,
			percgDestination = 1,
			percgFlowId = 0,
			percgIsData = percg.PROTO_CONTROL,
			percc1IsForward = percc1.IS_FORWARD,
			percc1IsExit = percc1.IS_NOT_EXIT,
			percc1Hop = 0,
			percc1MaxHops = 0,
			ethSrc = 0,
			ethDst = "10:11:12:13:14:15",						
			ethType = eth.TYPE_PERCG
		}
	end)
	endHost = EndHost.new(mem, dev, readyInfo.id, PKT_SIZE) 
	waitTillReady(readyInfo)

	while dpdk.running() do		      
	      dpdk.sleepMillis(1000)
	      endHost:resetPendingMsgs()

	      -- Handle updates on rx queue	     
	      if endHost:tryRecv() > 0 then 
	         --print("handle " .. endHost.rx .. " updates on rx queue") 
	      	 endHost:handleRxUpdates() 
	      end	

	      -- Handle new flow updates
	      local msgs = acceptMsgs(pipes, "pipeFlowStart")
	      if next(msgs) ~= nil then 
	         --print("handle " .. #msgs .. " updates on pipe flow start") 
	      	 endHost:handleNewFlows(msgs,  pipes)  
	      end

	      -- Handle flow completion updates ..
	      local msgs = acceptMsgs(pipes, "pipeFlowCompletions1")
	      if next(msgs) ~= nil then 
	         --print("handle " .. #msgs .. " updates on pipe flow completions") 
	      	 endHost:handleFlowCompletions(msgs) 
	      end	    

	      -- Send control packets in response to rx/ new flow updates
	      if endHost.numPendingMsgs > 0 then
	         --print("send " .. endHost.numPendingMsgs .. " pending messages") 
	      	 endHost:sendPendingMsgs() 
	      end
	      endHost:changeRates()
	end -- ends while
	dpdk.sleepMillis(5000)
end


function sendMsgs(pipes, pipeName, msg)	 
	 -- update send time for this pipe in msg.flowEvent.
	 -- and can turn off logging
	 if msg.flowEvent ~= nil and msg.flowEvent[pipeName] ~= nil then
	    local timeMs = dpdk.getTime()*1000
	    msg.flowEvent[pipeName]["send"] = timeMs	    
	  end
	  pipes[pipeName]:send(msg)

end

function acceptMsgs(pipes, pipeName) 
	if pipes == nil or pipes[pipeName] == nil then
	   --print("acceptMsgs on nil pipe! return!!")
	   return
	end 

	local pipe = pipes[pipeName]
	local numMsgs = pipe:count()
	if numMsgs ~= 0 then
	   --print(tostring(numMsgs) .. " msgs on pipe " .. pipeName)	
	   end
	local msgs = {}
	while numMsgs > 0 do
	      local msg = pipe:recv()
	      if msg.flowEvent ~= nil and msg.flowEvent[pipeName] ~= nil then
	      	 --print("Accepted msg on " .. tostring(pipeName) .. " for flow " .. tostring(msg.flow))
	      	 local timeMs = dpdk.getTime()*1000
	    	 msg.flowEvent[pipeName]["accept"] = timeMs
	    	 end
	      msgs[numMsgs] = msg
	      --print("Got msg # " .. tostring(numMsgs) .. " for flow " .. tostring(msg.flow) .. " on pipe " .. pipeName)
	      numMsgs = numMsgs - 1
        end
	return msgs
end	 

function loadTxDataSlave(dev, controlQueue, pipes, readyInfo)
        local setupStartTimeUs = dpdk.getTime() * 10e6
	print("starting loadTxDataSlave")
	local flowMsgs = {}
	local flowSize = {}
	local queues = {}
	local flowsList = {}
	local pendingFlowCompletions = {}
	local ctr = stats:newDevTxCounter(dev, "plain")

	local setupEndTimeUs = dpdk.getTime() * 10e6
	 -- tell others we're ready and check if others are ready
	 waitTillReady(readyInfo)

        local setupReadyTimeUs = dpdk.getTime() * 10e6

	print("For data, setup took " .. tostring(setupEndTimeUs-setupStartTimeUs) .. " us, syncing ready with others took " .. tostring(setupReadyTimeUs-setupEndTimeUs) .. " us")

	-- TODO(lav):  No preamble here, so uses default?? Also, pktLength??
	local mem = memory.createMemPool(function(buf)
		buf:getPercgPacket():fill{
			pktLength = PKT_SIZE,
			percgSource = readyInfo.id,
			percgDestination = 1,
			percgFlowId = 0,
			percgIsData = percg.PROTO_DATA,
			ethSrc = 0,
			ethDst = "10:11:12:13:14:15",						
		}
	end)
	bufs = mem:bufArray(128)

	
	local i = 0
	while dpdk.running() do	
	      -- TODO(lav): could be lazy about this?
	      local msgs = acceptMsgs(pipes, "pipeFlowStartData")
	      if next(msgs) ~= nil then
	         for msgNo, msg in pairs(msgs) do
		    print("Adding queue " .. tostring(msg.queue) .. " for flow " .. tostring(msg.flow) .. " to queues")
	  	    flowMsgs[msg.flow] = msg
		    flowSize[msg.flow] = msg.size
		    queues[msg.flow] = msg.queue
		    table.insert(flowsList, msg.flow)			 
		    end		
		  end -- ends if next(msgs)..
		  
	      -- put data packets on queue for each active flow	     
	      for flow, queueNo in pairs(queues) do	      	  
		  local numPacketsLeft = flowSize[flow]
		  --print(tostring(numPacketsLeft) .. " packets left for flow " .. flow)
		  if numPacketsLeft > 128 then
		      bufs:alloc(PKT_SIZE) 
		      flowSize[flow] = flowSize[flow] - 128
		      else
		      bufs:allocN(PKT_SIZE, numPacketsLeft) 
		      flowSize[flow] = flowSize[flow] - numPacketsLeft
		      table.insert(pendingFlowCompletions, flow)
		      end
		      
		   -- TODO(lav): or pre-allocate buffers per queue?
		   local queue = dev:getTxQueue(queueNo)
		   for _, buf in ipairs(bufs) do
			local pkt = buf:getPercgPacket()
			pkt.percg:setFlowId(tonumber(flow))
			pkt.eth.src:set(queueNo)
			end		    
		    print("sending packets of flow " .. tostring(flow))
		    queue:send(bufs)
		    ctr:update()
	      	  end
	      
	      if next(pendingFlowCompletions) ~= nil then
	      	 for flow, flowNum in pairs(pendingFlowCompletions) do
		         flowSize[flow] = nil
		         queues[flow] = nil
			 local msg = flowMsgs[flowNum]
			 sendMsgs(pipes, "pipeFlowCompletions1", msg)
			 sendMsgs(pipes, "pipeFlowCompletions2", msg)
		     	 end
		  pendingFlowCompletions = {}
	          end

	      i = i + 1
	end
	ctr:finalize()
end
