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
local EndHost = require "examples.perc.end_host"

local PKT_SIZE	= 80

control1Mod = {}

-- handles flow start messages from applications - to send first control, assign a free queue for data
-- handles flow completion message from "data slave", sends exit packet to free up bandwidth, reclaims queue
-- receives control packets on rx queue, computes new bottleneck info and sends out new packets
-- adjusts rates of data queues based on rxd control packets

function control1Mod.controlSlave(dev, pipes, readyInfo)
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

return control1Mod
