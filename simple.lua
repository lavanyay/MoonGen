local timer = require("timer")
local ffi = require("ffi")
local pkt = require("packet")
local filter    = require "filter"
local dpdk	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local pipe		= require "pipe"
local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"
local pcap = require "pcap"

function master(...)	 

   print("hello")
   --collectgarbage("stop")
   -- cores 1..7 part of CPU 1 in socket 1
	 -- port 0 is attached to socket 1
	 -- cores 8..16 part of CPU 2 in socket 2
	 -- port 1 is attached to socket 2
	 local numArgs = table.getn(arg)
	 
	 print("Got " .. numArgs .. " command-line arguments.")

	 local thisCore = dpdk.getCore()
	 local numCores = 8
	 local dev_0 = device.config{ port = 0, txQueues = 1, rxQueues = 1}
	 local dev_1 = device.config{ port = 1, txQueues = 1, rxQueues = 1}
	 local dev_2 = device.config{ port = 2, txQueues = 1, rxQueues = 1}
	 local dev_3 = device.config{ port = 3, txQueues = 1, rxQueues = 1}

	 local numLinksUp = device.waitForLinks()

	 print("waiting for links")
	 if (numLinksUp == 4) then 
	    dpdk.setRuntime(1000)
	    print("all 4 links are up")

	    

	    dpdk.launchLuaOnCore((thisCore+1)%numCores, "rxSlave", dev_1)
	    dpdk.launchLuaOnCore((thisCore+2)%numCores, "rxSlave", dev_2)
	    dpdk.launchLuaOnCore((thisCore+3)%numCores, "rxSlave", dev_3)
	    dpdk.launchLuaOnCore((thisCore+4)%numCores, "rxSlave", dev_0)


	    dpdk.launchLuaOnCore((thisCore+5)%numCores, "txSlave", dev_1)
	    dpdk.launchLuaOnCore((thisCore+6)%numCores, "txSlave", dev_2)
	    dpdk.launchLuaOnCore((thisCore+7)%numCores, "txSlave", dev_3)
	    --dpdk.launchLuaOnCore((thisCore+8)%numCores, "txSlave", dev_0)
	    --txSlave(dev_0)
	    
	    dpdk.waitForSlaves()
	    else print("Not all devices are up")
	 end
end

function rxSlave(dev)
   local thisCore = dpdk.getCore()
   print("Core " .. thisCore .. " receiving on device " .. dev.id)
   local rxQueue = dev:getRxQueue(0)
   local rxBufs = memory.bufArray()
   local runtime = timer:new(10)
   while runtime:running() and dpdk.running() do
      local rx = rxQueue:recv(rxBufs)
      for i=1,rx do
	 local buf = rxBufs[i]
	 local pkt = buf:getEthernetPacket()
	 print("Device " .. dev.id
	       .. " received ethernet packet for "
		  .. pkt.eth:getDst())	 
      end
   end
end

function txSlave(dev)
   local PKT_SIZE = 65
   local thisCore = dpdk.getCore()
   print("Core " .. thisCore .. " sending on device " .. dev.id)
   local mem = memory.createMemPool{
      --bufSize = 128,
      func = function(buf)
	 local pkt = buf:getPercgPacket()
	 pkt:fill{
	    pktLength = PKT_SIZE,
	    ethSrc="11:11:11:11:11:11",
	    ethDst="22:22:22:22:22:22",
	    ethType=eth.TYPE_DATA,
	    percgIsData=percg.PROTO_DATA,
	    percgFlowId=0,
	    percgSource=0,
	    percgDestination=1
	 }
      end
   }

   local addrList = {
      "11:11:11:11:11:11",
      "22:22:22:22:22:22",
      "33:33:33:33:33:33",
      "44:44:44:44:44:44"
   }
   local numAddr = 4
   local numBufs = 12
   local bufs = mem:bufArray(numBufs)
   local txQueue = dev:getTxQueue(0)
   local pcapWriter = pcapWriter:newPcapWriter("sink-"..dev.id..".pcap")
   
   local runtime = timer:new(10)
   local firstBatch = true
   while runtime:running() and dpdk.running() do
      bufs:alloc(PKT_SIZE)

      local i = 0   
      while (i+numAddr <= numBufs) do
	 for addrNo, addr in ipairs(addrList) do
	    local pkt = bufs[i+addrNo]:getPercgPacket()
	    pkt.eth:setDstString(addr)
	    pkt.payload.uint16[0]=0xFFFF
	    pkt.payload.uint16[1]=0xFFFF
	    pkt.payload.uint16[2]=0xFFFF
	 end
	 i = i + numAddr
      end

      if firstBatch then
	 pcapWriter:write(bufs)
	 pcapWriter:close()
	 firstBatch = false
	 end

      bufs:freeAll()
      return
      --print("Sent 100 ethernet packets.\n")
   end
end
