local pkt = require("packet")
local dpdk	= require "dpdk"
local dpdkc	= require "dpdkc"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local pipe		= require "pipe"
local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"
local pcap = require "pcap"
local ipc = require "examples.perc.ipc"

local PKT_SIZE	= 60

data1Mod = {}


function data1Mod.dataSlave(dev, pipes, readyInfo)
	-- print("starting loadTxDataSlave")
	local numPacketsLeft = {}
	local queues = {}
	-- one counter for total data throughput
	--local ctr = stats:newDevTxCounter(dev, "plain")
	ipc.waitTillReady(readyInfo)

	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = PKT_SIZE,
			ethSrc = queue,
			ethDst = "10:11:12:13:14:15", -- ready info id??
			ip4Dst = "192.168.1.1",
			udpSrc = 1234, -- flow id
			udpDst = 5678,	
		}
	end)
	-- TODO(lav): why 128?
	bufs = mem:bufArray(128)
	-- print("dataSlave: created bufArray")
	
	-- per flow state: numPacketsLeft, queues
	--  all indexed by flow and table of flows	
	local i = 0
	while dpdk.running() do	   
	   local now = dpdk.getTime()
	   local msgs = ipc.acceptFcdStartMsgs(pipes)
	   if next(msgs) ~= nil then
	      -- print("dataSlave: accepted FcdStartMsgs")
	      for msgNo, msg in pairs(msgs) do
		 numPacketsLeft[msg.flow] = msg.size
		 queues[msg.flow] = msg.queue
	      end		
	   end -- ends if next(msgs)..

	   -- TODO(lav): some way to avoid copying all remaining bytes every time?	   
	   --  what if queue doesn't have any more room. 
	   --  say cuz of insufficient credits??	case for s/w rate limiting?
	   for flow, queueNo in pairs(queues) do
	      local numLeft = numPacketsLeft[flow]
	      --print("sending " .. numLeft .. " for "
	      --	       .. flow .. " on " .. queueNo)
	      assert(numLeft >= 0)	      
	      local queue = dev:getTxQueue(queueNo)
		 
	      local numToSend = 128
	      if numLeft < 128 then numToSend = numLeft end
	      bufs:allocN(PKT_SIZE, numToSend)

	      for i=1,numToSend do		 
		 local pkt = bufs[i]:getUdpPacket()
		 pkt.udp:setSrcPort(tonumber(flow))
		 pkt.eth.src:set(queueNo)
	      end

	      local numSent = queue:trySendN(bufs, numToSend)
	      --ctr:update()
	      numLeft = numLeft - numSent
	      --print("Sent " .. numSent .. " packets of flow " .. flow
	      -- 	       .. ", " .. numLeft .. " to go")
	      assert(numLeft >= 0)	      
	      numPacketsLeft[flow] = numLeft
	      if (numLeft == 0) then
		 local now = dpdk.getTime()
		 numPacketsLeft[flow] = nil
		 queues[flow] = nil
		 -- TODO(lav): risky? setting value for existing key to nil, while iterating over table
		 ipc.sendFdcEndMsg(pipes, flow, now)
	      end
	   end -- ends for flow, queueNo in queues	   
	   i = i + 1
	end -- ends while dpdk.running()
	--ctr:finalize()
end

return data1Mod
