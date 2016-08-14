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
local log = require "log"
local DATA_PACKET_SIZE	= perc_constants.DATA_PACKET_SIZE
-- includes payload
local ACK_PACKET_SIZE = perc_constants.ACK_PACKET_SIZE

ffi.cdef [[
typedef struct foo { bool active; 
uint64_t flow, size, sent, acked; double acked_time;} txQueueInfo;
typedef struct bar {uint64_t flow, recv, acked, size;} rxQueueInfo;
]]

data2Mod = {}

function data2Mod.rxlog(str)
   if perc_constants.LOG_RXDATA then
      print("data2.lua rx log: " .. str)
   end
end

function data2Mod.txlog(str)
   if perc_constants.LOG_TXDATA then
      print("data2.lua tx log: " .. str)
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
   data2Mod.rxlog("Data rx slave running on dev "
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
   local queueInfo = ffi.new("rxQueueInfo[?]",
   			     perc_constants.MAX_QUEUES+1, {}) -- indexing from 1
   -- invariants
   for q=1,perc_constants.MAX_QUEUES do
      queueInfo[q].recv = 0ULL
      queueInfo[q].size = 0ULL
      queueInfo[q].acked = 0ULL
   end
   
   local txQueue = dev:getTxQueue(perc_constants.ACK_TXQUEUE)
   local rxQueue = dev:getRxQueue(perc_constants.DATA_RXQUEUE)
   local rxCtr = stats:newDevRxCounter(rxQueue, "plain")
   local rxBufs = memory.bufArray()
   local seq = 0ULL
   local lastAckTime = dpdk.getTime()

   while dpdk.running() do
      --data2Mod.rxlog("receive data packets\n")
      local ackNow = false      
      do
	 local rx = dpdkc.rte_eth_rx_burst_export(rxQueue.id,
						  rxQueue.qid,
						  rxBufs.array,
						  rxBufs.size) --rxQueue:recv(rxBufs)
	 for b = 1, rx do
	    local buf = rxBufs[b]
	    local pkt = buf:getPercgPacket()
	    -- assert(pkt.eth:getType() == eth.TYPE_PERC_DATA)
	    local flow = pkt.payload.uint64[0]
	    local q = pkt.payload.uint64[1]
	    -- local seqNo = pkt.payload.uint64[2]	
	    -- local checksumRx = pkt.payload.uint64[3]
	    local size = pkt.payload.uint64[4]
	    -- local checksumC = flow + q + seqNo
	    -- if (checksumRx ~= checksumC) then
	    --    data2Mod.warn("checksum doesn't match recvd for data pkt "
	    -- 			.. pkt.percg:getString()
	    -- 			.. " flow " .. tostring(flow)
	    -- 			.. " q " .. tostring(q)
	    -- 			.. " seqNo " .. tostring(seqNo)
	    -- 			.. " checksumRx " .. tostring(checksumRx)
	    -- 			.. " computed " .. tostring(checksumC))
	    -- end
	    -- assert(checksumRx == checksumC)
	    if queueInfo[q].flow ~= flow then
	       queueInfo[q].flow = flow 
	       queueInfo[q].recv = 0ULL
	       queueInfo[q].acked = 0ULL
	       queueInfo[q].size = size
	    --    -- data2Mod.rxlog("rx set up queue " .. q
	    --    -- 		      .. " for flow " .. tostring(flow)
	    --    -- 			 .. " recv " .. tostring(queueInfo[q].recv)
	    --    -- 			 .. " acked " .. tostring(queueInfo[q].acked)
	    --    -- 			 .. ", flow size " .. tostring(queueInfo[q].size))
	    end
	    -- assert(seqNo < size)
	    assert(queueInfo[q].size == size)	   
	    queueInfo[q].recv = queueInfo[q].recv + 1
	    if (queueInfo[q].recv == queueInfo[q].size) then
	       ackNow = true
	    end
	    -- if (queueInfo[q].recv >  queueInfo[q].size) then
	    --     data2Mod.warn("rx received more packets than size"
	    --  		      .. " for flow " .. tostring(flow)
	    --  			 .. " size " .. tostring(queueInfo[q].size)
	    --  			 .. " < recv " .. tostring(queueInfo[q].recv))
	    -- end	 
	    assert(queueInfo[q].recv <= queueInfo[q].size)	    
	 end
	 if rx > 0 then
	    rxCtr:update()
	    rxBufs:freeAll()
	    end
      end      

      -- TODO(lav): maybe ACK periodically instead
      --  of every DPDK loop, or if flows can send
      -- total size too, then ACK immediately if
      -- total size = recv else periodically
      do
      	 local now = dpdk.getTime()
      	 if false and now > lastAckTime + perc_constants.rx_ack_timeout
      	 or ackNow then
      	    lastAckTime = now
      	    local newAcks = 0
      	    for q=1,perc_constants.MAX_QUEUES do
      	       assert(queueInfo[q].recv <= queueInfo[q].size)
      	       if queueInfo[q].recv > queueInfo[q].acked then
      		  newAcks = newAcks + 1 end
      	    end
	    if newAcks > 0 then
	       txBufs:allocN(ACK_PACKET_SIZE, newAcks)	    
	       local b = 1
	       for q=1,perc_constants.MAX_QUEUES do	 
		  if queueInfo[q].recv > queueInfo[q].acked then
		     queueInfo[q].acked = queueInfo[q].recv
      		  assert(b <= newAcks)
      		  local pkt = txBufs[b]:getPercgPacket()
      		  b = b + 1
      		  pkt.payload.uint64[0] = queueInfo[q].flow 
      		  pkt.payload.uint64[1] = q -- lua number -> double -> 32b
      		  pkt.payload.uint64[2] = queueInfo[q].acked
      		  pkt.payload.uint64[3] = queueInfo[q].flow
      		     + pkt.payload.uint64[1] + queueInfo[q].recv
      		  pkt.payload.uint64[4] = queueInfo[q].size
      		  pkt.eth:setType(eth.TYPE_ACK)
      		  pkt.eth:setSrc(perc_constants.ACK_TXQUEUE)
		  end
	       end
	       txQueue:send(txBufs)
	    end
      	 end -- ends if ackTime..	 
      end -- ends do

   end -- ends while dpdk.running
   rxCtr:finalize()
   data2Mod.rxlog("dpdk running on rxslave " .. tostring(dpdk.running()))
end
   
-- sends data packets and receives acks
function data2Mod.txSlave(dev, ipcPipes, readyInfo, monitorPipe)
   local thisCore = dpdk.getCore()
   data2Mod.txlog("Data tx slave running on dev "
		   .. dev.id .. ", core " .. thisCore)
   assert(ipcPipes ~= nil)
   ipc.waitTillReady(readyInfo)
   local mem = {}
   local txBufs = {}

   for q = 1, perc_constants.MAX_QUEUES do
      mem[q] = memory.createMemPool(
	 function(buf)
	    buf:getPercgPacket():fill{
	       pktLength = DATA_PACKET_SIZE,
	       ethType = eth.TYPE_PERC_DATA}
      end)   
      txBufs[q] = mem[q]:bufArray()
   end
   
   local queueInfo = ffi.new("txQueueInfo[?]", perc_constants.MAX_QUEUES+1) -- indexing from 1
   local rxQueue = dev:getRxQueue(perc_constants.ACK_RXQUEUE)
   local rxBufs = memory.bufArray()

   local txCtr = stats:newDevTxCounter(dev, "plain")
   local txQueues = {}
   for q=1,perc_constants.MAX_QUEUES do
      txQueues[q] = dev:getTxQueue(q)
   end
   
   while dpdk.running() do      
      do -- (get start messages)
	 --data2Mod.txlog("get start msgs")
	 local now = dpdk.getTime()	 
	 local msgs = ipc.acceptFcdStartMsgs(ipcPipes)
	 --if next(msgs) == nil then data2Mod.txlog("Got no messages from ipcPipes") end
	 for _, msg in ipairs(msgs) do
	    local q = msg.queue
	    queueInfo[q].flow = msg.flow
	    queueInfo[q].size = msg.size
	    queueInfo[q].sent = 0
	    queueInfo[q].acked = 0
	    queueInfo[q].active = true
	    queueInfo[q].acked_time = now
	    data2Mod.txlog("Starting a queue for " .. msg.flow
			      .. " size " .. tostring(queueInfo[q].size)
			      .. " sent " .. tostring(queueInfo[q].sent)
			      .. " acked " .. tostring(queueInfo[q].acked)
			      .. " active " .. tostring(queueInfo[q].active)
			      .. " acked_time " .. tostring(queueInfo[q].acked_time))
	 end
      end -- ends do (get start messages)

      do -- (send data packets)
	 --data2Mod.txlog("send data packets")
	 local now = dpdk.getTime()	 
	 for q=1,perc_constants.MAX_QUEUES do
	    assert(queueInfo[q].size >= queueInfo[q].sent)
	    if queueInfo[q].active and queueInfo[q].sent < queueInfo[q].size then
	       if queueInfo[q].sent + 63ULL > queueInfo[q].size then 
		  txBufs[q]:allocN(
		     DATA_PACKET_SIZE,
		     tonumber((queueInfo[q].size - queueInfo[q].sent)))
	       else
		  txBufs[q]:alloc(DATA_PACKET_SIZE)
	       end	       
	       data2Mod.txlog(
		  "queue " .. q
		     .. " is active and has"
		     .. " sent " .. tostring(queueInfo[q].sent)
		     .. " of size " .. tostring(queueInfo[q].size)
		     .. " so toSend " .. tostring(txBufs[q].size)
		     .. " packets of " .. tostring(queueInfo[q].flow))

	       for _, buf in ipairs(txBufs[q]) do
		  local pkt = buf:getPercgPacket()
		  pkt.percg:setFlowId(queueInfo[q].flow) -- 32b -> 16b
		  pkt.payload.uint64[0] = queueInfo[q].flow
		  pkt.payload.uint64[1] = q
		  pkt.payload.uint64[2] = queueInfo[q].sent
		  pkt.payload.uint64[3] =
		     pkt.payload.uint64[0]
		     + pkt.payload.uint64[1]
		     + pkt.payload.uint64[2]
		  pkt.payload.uint64[4] = queueInfo[q].size
		  pkt.eth:setSrc(q)
		  pkt.eth:setType(eth.TYPE_PERC_DATA)
		  queueInfo[q].sent = queueInfo[q].sent + 1		  
	       end
	       txCtr:update()
	       txQueues[q]:send(txBufs[q])

	       if (queueInfo[q].sent == queueInfo[q].size) then
		  ipc.sendFdcFinMsg(
		     ipcPipes, tonumber(queueInfo[q].flow), now)
	       end
	    end
	    
	    if queueInfo[q].active then
	       local acked_time = tonumber(queueInfo[q].acked_time)
	       if now > acked_time
	       + perc_constants.tx_ack_timeout then
		  local logFunc = data2Mod.txlog
		  if queueInfo[q].acked == 0 then
		     logFunc = data2Mod.warn
		  end
		  logFunc("sending fin-ack for "
			     .. tostring(queueInfo[q].flow)
			     .. " acked "
			     .. tostring(queueInfo[q].acked)
			     .. " of " .. tostring(queueInfo[q].size)
			     .. " packets.")		  
	       
		  ipc.sendFdcFinAckMsg(ipcPipes,
				       tonumber(queueInfo[q].flow),
				       tonumber(queueInfo[q].acked),
				       tonumber(acked_time))
		  queueInfo[q].active = false
	       end -- ends if acked_time ..
	    end  -- ends if queue.. active
	 end  -- ends for q=1,perc_constants.MAX_QUEUES
      end  -- ends do (send data packets)
      
      do -- (receive acks)
	 --data2Mod.txlog("receive acks")
	 local now = dpdk.getTime()
	 local rx = rxQueue:tryRecv(rxBufs, 20)
	 for b = 1 , rx do
	    local pkt = rxBufs[b]:getPercgPacket()
	    local flow = pkt.payload.uint64[0]
	    local q = pkt.payload.uint64[1]
	    local acked = pkt.payload.uint64[2]
	    local checksumRx = pkt.payload.uint64[3]
	    local checksumC = pkt.payload.uint64[0] + pkt.payload.uint64[1] + pkt.payload.uint64[2]
	    -- if (checksumRx ~= checksumC) then
	    --    data2Mod.warn(
	    -- 	  "checksum doesn't match recvd for ack "
	    -- 	     .. pkt:getString())
	    -- end
	    assert(checksumRx == checksumC)
	    if (queueInfo[q].active
		   and queueInfo[q].flow == flow
		and pkt.payload.uint64[2] > queueInfo[q].acked) then	       
	       queueInfo[q].acked = pkt.payload.uint64[2]
	       queueInfo[q].acked_time = now
	       assert(queueInfo[q].acked <= queueInfo[q].size)
	    else
	       assert(false)
	       -- data2Mod.warn(
	       -- "tx got ack for inactive queue "
	       --  .. q .. ", flow " .. flow
	       --  .. "acked " .. acked)
	    end
	 end
	 rxBufs:freeAll()
      end -- ends do (receive acks)
   end -- ends while dpdk.running()
   txCtr:finalize()
end

return data2Mod
