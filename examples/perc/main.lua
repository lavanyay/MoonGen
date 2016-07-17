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

local ipc = require "examples.perc.ipc"

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

	    local pipesTxDev = ipc.getInterVmPipes()
	    local pipesRxDev = ipc.getInterVmPipes() 
	    local readyPipes = ipc.getReadyPipes(3) -- control and application on dev0, control on dev1

	    dpdk.launchLuaOnCore(core1, "loadControlSlave", txDev, pipesTxDev, {["pipes"]= readyPipes, ["id"]=1})
	    dpdk.launchLuaOnCore(core2, "loadControlSlave", rxDev, pipesRxDev, {["pipes"]= readyPipes, ["id"]=2})

	    loadApplicationSlave2(pipesTxDev, {["pipes"]= readyPipes, ["id"]=3})
	    dpdk.waitForSlaves()
	    else print("Not all devices are up")
	 end
end




function startNewFlow(newFlowId, active, pipes)
   table.insert(active, newFlowId)
   ipc.sendFacStartMsg(pipes, newFlowId, 2)
   -- local facStartMsg = ipc.getFacStartMsg(newFlowId, 3)
   
   -- print("created cdata object of type fac_start_t with flow "
   --	    .. facStartMsg[0].flow .. ", destination "
   --	    .. facStartMsg[0].destination .. "\n")
   
   --ipc.sendMsgs(pipes, "fastPipeAppToControlStart",
   --		{["flow"] = tostring(newFlowId), ["destination"]="3"})
end

function endOldFlow(active, pipes)
   local removeFlowId = table.remove(active)
   --	    .. ", new # flows: " .. numFlows .. "\n")

   ipc.sendFacEndMsg(pipes, removeFlowId)
   return removeFlowId
end

function loadApplicationSlave2(pipes, readyInfo)
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
	 numFlows = numFlows + workload[seqNo]
	 assert(numFlows >= 0)	 
	 if workload[seqNo] > 0 then
	    startNewFlow(newFlowId,active, pipes)
	    print(now .. ": add " .. newFlowId
		     .. ", new # flows: " .. numFlows .. "\n")
	    newFlowId = newFlowId+1
	 else
	    removeFlowId = endOldFlow(active, pipes)
	    print(now .. ": remove " .. removeFlowId
		     .. ", new # flows: " .. numFlows .. "\n")

	 end
	 seqNo = seqNo + 1
	 lastSentTime = dpdk.getTime()     
      end
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
	endHost = EndHost.new(mem, dev, readyInfo.id, pipes, PKT_SIZE) 
	ipc.waitTillReady(readyInfo)

	local lastRxTime = 0
	local lastTxTime = 0
	while dpdk.running() do		      
	      --dpdk.sleepMillis(1000)
	      endHost:resetPendingMsgs()

	      -- Handle updates on rx queue	     
	      if endHost:tryRecv() > 0 then
		 local rxTime = dpdk.getTime()
	         --print(endHost.rx .. " updates on rx queue in "
		 --	  .. ((rxTime - lastRxTime)*1e6) .. " us") 
	      	 endHost:handleRxUpdates(rxTime)
		 lastRxTime = rxTime
	      end	

	      -- Handle new flow updates
	      local msgs = ipc.acceptFacStartMsgs(pipes)
	      --, "fastPipeAppToControlStart")
	      if next(msgs) ~= nil then 
	         --print("handle " .. #msgs .. " updates on pipe flow start") 
	      	 endHost:handleNewFlows(msgs,  dpdk.getTime())  
	      end

	      -- Handle flow completion updates ..
	      local msgs = ipc.acceptFacEndMsgs(pipes)
	      if next(msgs) ~= nil then 
	         --print("handle " .. #msgs .. " updates on pipe flow completions") 
	      	 endHost:handleFlowCompletions(msgs) 
	      end	    

	      -- Send control packets in response to rx/ new flow updates
	      if endHost.numPendingMsgs > 0 then
		 local txTime = dpdk.getTime()
	      	 endHost:sendPendingMsgs(txTime)
		 --print("sent " .. endHost.numPendingMsgs
	         --		  .. " on tx queue in last " 
		 --	  .. ((txTime - lastTxTime)*1e6) .. " us")
		 lastTxTime = txTime
	      end
	      endHost:changeRates()
	end -- ends while
	dpdk.sleepMillis(5000)
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
	 ipc.waitTillReady(readyInfo)

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
	   local now = dpdk.getTime()
	   -- TODO(lav): could be lazy about this?
	   local msgs = ipc.acceptFcdStartMsgs(pipes)
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
		 --sendMsgs(pipes, "appToData", msg)
		 ipc.sendMsgs(pipes, "slowPipeControlToApp",
			      {["msg"] = ("end flow " .. flowNum),
				 ["now"] = now})
	      end
	      pendingFlowCompletions = {}
	   end
	   
	   i = i + 1
	end
	ctr:finalize()
end
