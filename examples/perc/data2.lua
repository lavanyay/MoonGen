local ntoh16, hton16 = ntoh16, hton16
local ffi = require("ffi")
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
local monitor = require "examples.perc.monitor"
local perc_constants = require "examples.perc.constants"
local DATA_PACKET_SIZE	= perc_constants.DATA_PACKET_SIZE
-- includes payload
local ACK_PACKET_SIZE = perc_constants.ACK_PACKET_SIZE

ffi.cdef [[
typedef struct foo { bool active; 
unsigned long flow, size, sent, acked; double acked_time;} txQueueInfo;
typedef struct bar {unsigned long flow, recv, acked;} rxQueueInfo;
]]

data2Mod = {}

function data2Mod.log(str)
   if perc_constants.LOG_DATA then
      print("data2.lua log: " .. str)
   end
end

function data2Mod.warn(str)
   if perc_constants.WARN_DATA then
      print("data2.lua warn: " .. str)
   end
end

-- receives data packets and sends acks
function data2Mod.rxSlave(dev, readyInfo)
   local thisCore = dpdk.getCore()
   data2Mod.log("Data rx slave running on dev "
		   .. dev.id .. ", core " .. thisCore
		   .. " dpdk running " .. tostring(dpdk.running()))
   
   ipc.waitTillReady(readyInfo)
   local mem = memory.createMemPool(
      function(buf) 
   	 buf:getPercgPacket():fill{
   	    pktLength = ACK_PACKET_SIZE,
   	    ethType = eth.TYPE_ACK,
   	    ethSrc = perc_constants.ACK_TXQUEUE}
   end)
   local txBufs = mem:bufArray()
   --txBufs:alloc()
   local queueInfo = ffi.new("rxQueueInfo[?]", perc_constants.MAX_QUEUES+1) -- indexing from 1

   local txQueue = dev:getTxQueue(perc_constants.ACK_TXQUEUE)
   local rxQueue = dev:getRxQueue(perc_constants.DATA_RXQUEUE)
   local rxBufs = memory.bufArray()
   
   while dpdk.running() do
     -- data2Mod.log("receive data packets\n")
      local newAcks = 0
      do
	 local now = dpdk.getTime()
	 local rx = rxQueue:tryRecv(rxBufs, 100)
	 --if (rx == 0) then data2Mod.log("Rx slave received no data packets") end
	 for b=1,rx do
	    if b == 1 then data2Mod.log("rx got " .. rx .. " data packets.\n") end
	    local pkt = rxBufs[b]:getPercgPacket()
	    --data2Mod.log("packet has eth type " .. tostring(pkt.eth:getType()))
	    assert(pkt.eth:getType() == eth.TYPE_PERC_DATA)
	    local flow = pkt.payload.uint32[0]
	    local q = pkt.payload.uint32[1]
	    local seqNo = pkt.payload.uint32[2]
	    local checksumRx = pkt.payload.uint32[3]
	    local checksumC = flow + q + seqNo
	    if (checksumRx ~= checksumC) then
	       data2Mod.warn("checksum doesn't match recvd for data pkt " .. pkt.percg:getString() .. " flow " .. tostring(flow) .. " q " .. tostring(q)
				.. " seqNo " .. tostring(seqNo) .. " checksumRx " .. tostring(checksumRx) .. " computed " .. tostring(checksumC))
	    end
	    assert(checksumRx == checksumC)
	    local qi = queueInfo[q]
	    if tonumber(qi.flow) ~= tonumber(flow) then
	       qi.flow = flow -- lua number -> 64b
	       qi.recv = 0ULL
	       qi.acked = 0ULL
	    end
	    if (qi.recv == qi.acked) then newAcks = newAcks + 1 end
	    qi.recv = qi.recv + 1ULL
	 end
      end

      do
	 if newAcks > 0 then
	    data2Mod.log("rx slave has " .. newAcks .. " new acks and txBufs is ye big " .. txBufs.size)	    
	    assert(newAcks < txBufs.maxSize) -- one per queue on ly 30 queues in use
	    txBufs:allocN(ACK_PACKET_SIZE, newAcks)
	    local b = 1
	    for q=1,perc_constants.MAX_QUEUES do
	       local qi = queueInfo[q]	       
	       if qi.recv > qi.acked then
		  assert(b <= newAcks)
		  data2Mod.log("found an ack-able queue " .. q)
		  local pkt = txBufs[b]:getPercgPacket()
		  pkt.payload.uint32[0] = qi.flow -- 64b -> 32b
		  pkt.payload.uint32[1] = q -- lua number -> 32b
		  pkt.payload.uint32[2] = qi.recv
		  pkt.payload.uint32[3] = qi.flow + pkt.payload.uint32[1] + qi.recv
		  pkt.eth:setType(eth.TYPE_ACK)
		  qi.acked = qi.recv
		  if b == 1 then data2Mod.log("rx acking "
						 .. tostring(qi.acked) .. " packets"
						 .. " of flow " .. tostring(qi.flow)
					      .. " (queue " .. q .. ")") end
		  b = b + 1
	       end
	    end
	    txQueue:send(txBufs)
	 end
      end
   end -- ends while dpdk.running
   data2Mod.log("dpdk running on rxslave " .. tostring(dpdk.running()))
end
   
-- sends data packets and receives acks
function data2Mod.txSlave(dev, ipcPipes, readyInfo, monitorPipe)
   local thisCore = dpdk.getCore()
   data2Mod.log("Data tx slave running on dev "
		   .. dev.id .. ", core " .. thisCore)
   assert(ipcPipes ~= nil)
   ipc.waitTillReady(readyInfo)
   local mem = memory.createMemPool(
      function(buf)
	 buf:getPercgPacket():fill{
	    pktLength = DATA_PACKET_SIZE,
	    ethType = eth.TYPE_PERC_DATA}
   end)
   
   local txBufs = mem:bufArray()
   local queueInfo = ffi.new("txQueueInfo[?]", perc_constants.MAX_QUEUES+1) -- indexing from 1

   local rxQueue = dev:getRxQueue(perc_constants.ACK_RXQUEUE)
   local rxBufs = memory.bufArray()

   while dpdk.running() do
   
      
      do -- (get start messages)
	 --data2Mod.log("get start msgs")
	 local now = dpdk.getTime()	 
	 local msgs = ipc.acceptFcdStartMsgs(ipcPipes)
	 --if next(msgs) == nil then data2Mod.log("Got no messages from ipcPipes") end
	 for _, msg in ipairs(msgs) do
	    data2Mod.log("Starting a queue for " .. msg.flow)
	    local qi = queueInfo[msg.queue]
	    qi.flow = msg.flow
	    qi.size = msg.size
	    qi.sent = 0ULL
	    qi.acked = 0ULL
	    qi.active = true
	    qi.acked_time = now
	 end
      end -- ends do (get start messages)

      --data2Mod.log("Tx Slave Sending Data Packets")

      do -- (send data packets)
	 --data2Mod.log("send data packets")
	 local now = dpdk.getTime()	 
	 for q=1,perc_constants.MAX_QUEUES do
	    local qi = queueInfo[q] -- TODO(lav): check ref
	    if qi.active and qi.sent < qi.size then
	       data2Mod.log("queue " .. q .. " is active and "
			       .. " has sent only "
			       .. tonumber(qi.sent) .. " of "
			       .. tonumber(qi.size) .. "\n")
	       --print("size of txBufs is " .. txBufs.size)
	       assert(qi.size >= qi.sent)
	       local left = qi.size - qi.sent
	       local toSend = 63ULL
	       if left < 63ULL then toSend = left end
	       txBufs:allocN(DATA_PACKET_SIZE, tonumber(toSend))
	       local bufNo = 1ULL
	       for _, buf in ipairs(txBufs) do
		  local pkt = buf:getPercgPacket()
		  local seqNo = qi.sent + bufNo
		  pkt.percg:setFlowId(qi.flow) -- 64b -> 16b
		  pkt.payload.uint32[0] = qi.flow
		  pkt.payload.uint32[1] = q
		  pkt.payload.uint32[2] = seqNo
		  pkt.payload.uint32[3] = pkt.payload.uint32[0] + pkt.payload.uint32[1] + pkt.payload.uint32[2]
		  pkt.eth:setSrc(q)
		  pkt.eth:setType(eth.TYPE_PERC_DATA)
		  -- data2Mod.log("set up packet # " .. tostring(bufNo)
		  -- 		  .. "/ " .. tostring(toSend)
		  -- 		  .. " seqNo " .. tostring(pkt.payload.uint32[1])
		  -- 		  .. " or " .. tostring(seqNo)
		  -- 		  .. " queue " .. tostring(pkt.payload.uint32[1])
		  -- 		  .. " flow " .. tostring(pkt.payload.uint32[0]))
		  bufNo = bufNo + 1ULL
	       end
	       data2Mod.log("set up " .. tonumber(toSend)
			       .. " packets of " .. tonumber(qi.flow))
	       local queue = dev:getTxQueue(q)
	       data2Mod.log("Getting queue " .. q .. " of device " .. dev.id)
	       queue:send(txBufs)
	       data2Mod.log("tx sent " .. tonumber(toSend)
			       .. " of " .. tonumber(qi.size) .. " packets"
			       .. " of flow " .. tonumber(qi.flow) ..
			       " (queue " .. q .. ")")
	       qi.sent = qi.sent + toSend

	       if (qi.sent == qi.size) then
		  ipc.sendFdcFinMsg(ipcPipes, tonumber(qi.flow), now)
		  -- qi.active = false
		  -- TODO(lav): control thread should de-allocate
		  -- queue only after fin-ack
	       end
	    end
	    if qi.active then
	       local acked_time = tonumber(qi.acked_time)
	       if now > acked_time + perc_constants.timeout_interval then
		  if qi.acked == 0 then logFunc = data2Mod.warn else logFunc = data2Mod.log end
		  logFunc("sending fin-ack for " .. tonumber(qi.flow)
				     .. " acked " .. tonumber(qi.acked)
				     .. " of " .. tonumber(qi.size)
				     .. " packets.")		  
	       
		  ipc.sendFdcFinAckMsg(ipcPipes,
				       tonumber(qi.flow),
				       tonumber(qi.acked),
				       tonumber(acked_time))
		  qi.active = false
	       end -- ends if acked_time ..
	    end  -- ends if queue.. active
	 end  -- ends for q=1,perc_constants.MAX_QUEUES
      end  -- ends do (send data packets)
      
      do -- (receive acks)
	 --data2Mod.log("receive acks")
	 local now = dpdk.getTime()
	 local rx = rxQueue:tryRecv(rxBufs, 100)
	 for b=1,rx do
	    if (b==1) then data2Mod.log("received " .. rx .. " acks") end
	    local pkt = rxBufs[b]:getPercgPacket()
	    local flow = pkt.payload.uint32[0]
	    local q = pkt.payload.uint32[1]
	    local acked = pkt.payload.uint32[2]
	    local checksumRx = pkt.payload.uint32[3]
	    local checksumC = pkt.payload.uint32[0] + pkt.payload.uint32[1] + pkt.payload.uint32[2]
	    if (checksumRx ~= checksumC) then
	       data2Mod.warn("checksum doesn't match recvd for ack "
				.. pkt:getString())
	       end
	    assert(checksumRx == checksumC)
	    if (queueInfo[q].active
		   and queueInfo[q].flow == flow
		and acked > queueInfo[q].acked) then	       
	       queueInfo[q].acked = acked
	       queueInfo[q].acked_time = now
	    else
	       data2Mod.warn("tx got ack for inactive queue "
			       .. q .. ", flow " .. flow
			       .. "acked " .. acked)
	    end
	    data2Mod.log("received ack # " .. b .. "/ " .. rx .. " at " .. tostring(acked_time) .. " and now " .. tostring(now))
	 end
	 --data2Mod.log("txSlave freeing rxbufs")
	 rxBufs:freeAll()
      end -- ends do (receive acks)

      --data2Mod.log("dpdk.running : " .. tostring(dpdk.running()))
   end -- ends while dpdk.running()
end

return data2Mod
