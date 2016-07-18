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

local PKT_SIZE	= 80

data1Mod = {}


function dataSlave(dev, controlQueue, pipes, readyInfo)
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
