local dpdk		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"

local percg = require "proto.percg"
local percc1 = require "proto.percc1"
local eth = require "proto.ethernet"

local Link = require "examples.perc.perc_link"
local EndHost = require "examples.perc.end_host"

local PKT_SIZE	= 80

-- sudo ./build/MoonGen examples/perc/control-throughput.lua 0:1 1:1

function master(...)
	local devices = { ... }
	if #devices == 0 then
		return print("Usage: txport[:numcores] [rxport:[numcores] ...]")
	end

	if type(devices[1] == "string") then
	   txId, txCores  = tonumberall(devices[1]:match("(%d+):(%d+)"))
	else txId, txCores = devices[1], 1
	end

	if type(devices[2] == "string") then
	   rxId, rxCores  = tonumberall(devices[2]:match("(%d+):(%d+)"))
	else rxId, rxCores = devices[2], 1
	end

	txDev = { device.config{ port = txId, txQueues = txCores }, txCores }
	rxDev = { device.config{ port = rxId, rxQueues = rxCores }, rxCores }
		
	device.waitForLinks()

	txDev, txCores = unpack(txDev)
	for i = 1, txCores do
	   dpdk.launchLua("loadSlave", txDev, txDev:getTxQueue(i - 1), i == 0)
	end

	rxDev, rxCores = unpack(rxDev)
	-- TODO(lav): run on all rx cores
	local rx = dpdk.launchLua("rxSlave", rxDev:getRxQueue(0), PKT_SIZE, 1 == 1)

	dpdk.waitForSlaves()
end

function initPercc1(buf, len)
   buf:getPercc1Packet():fill{
      pktLength = len,
      ethSrc = queue,
      ethDst = "10:11:12:13:14:15",
      percgFlowId = 1,
      percgDestination = 2,
      percgSrc = 3,
      percc1IsExit = percc1.IS_EXIT,
      percc1IsForward = percc1.IS_NOT_FORWARD,
      percc1NewRate1 = percc1.RATE_INFINITE,
      percc1OldRate1 = percc1.RATE_INFINITE,
      percc1NewLabel1 = percc1.LABEL_UNSAT,
      percc1OldLabel1 = percc1.LABEL_UNDEF,
      percc1LinkCapacity1 = percc1.RATE_INFINITE,
      percc1SumSat1 = 0,
      percc1NumSat1 = 0,
      percc1NumUnsat1 = 1,
      percc1NewRate2 = percc1.RATE_INFINITE,
      percc1OldRate2 = percc1.RATE_INFINITE,
      percc1NewLabel2 = percc1.LABEL_UNSAT,
      percc1OldLabel2 = percc1.LABEL_UNDEF,
      percc1LinkCapacity2 = percc1.RATE_INFINITE,
      percc1SumSat2 = 0,
      percc1NumSat2 = 0,
      percc1NumUnsat2 = 1,
  }
end


function loadSlave(dev, queue, showStats)
	local mem = memory.createMemPool(function(buf)
	      initPercc1(buf, PKT_SIZE)
	end)
	bufs = mem:bufArray(128)
	--local baseIP = parseIPAddress("10.0.0.1")
	--local flow = 0
	local ctr = stats:newDevTxCounter(dev, "plain")
	while dpdk.running() do
		bufs:alloc(PKT_SIZE)
		--for _, buf in ipairs(bufs) do
		--	local pkt = buf:getPercgPacket()
		--	pkt.ip4.src:set(baseIP + flow)
		--	flow = incAndWrap(flow, numFlows)
		-- end
		-- UDP checksums are optional, so just IP checksums are sufficient here
		--bufs:offloadIPChecksums()
		queue:send(bufs)
		if showStats then ctr:update() end
	end
	if showStats then ctr:finalize() end
end


function rxSlave(queue, size, showStats)
	local bufs = memory.bufArray()
	local ctr = stats:newManualRxCounter(queue.dev, "plain")
	while dpdk.running() do
		local rx = queue:tryRecv(bufs, 10)
		bufs:freeAll()
		if showStats then ctr:updateWithSize(rx, size) end
	end
	if showStats then ctr:finalize() end
	return nil -- TODO
end
