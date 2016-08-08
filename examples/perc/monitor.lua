local ffi = require("ffi")
local dpdk	= require "dpdk"
local ipc = require "examples.perc.ipc"
local pipe		= require "pipe"
local perc_constants = require "examples.perc.constants"

monitorMod = {
   ["typeDataTxMbps"]=1,
   ["typeDataRxMbps"]=2,
   ["typeDataTxQueueMbps"]=3,
   ["typeDataRxQueueMbps"]=4,
   ["typeDataTxQueueB"]=5,
   ["typeDataRxQueueB"]=6,
   ["typeAppActiveFlowsNum"]=7,
   ["typeSetFlowTxRate"]=8,
   ["typeGetFlowBottleneckRate"]=9,
   ["typeFlowTxRateConfigured"]=10,
   ["typeControlDpdkLoopStartTime"]=11,
   ["typeCorruptedDataPkts"]=12,
   ["typeFlowFctLoss"]=13,
   ["typeDataStatsPerDpdkLoop"]=14, --us
   ["typeControlStatsPerDpdkLoop"]=15, --us
   ["typeNumActiveQueues"]=16,
   ["typeControlPacketRtt"]=17, --us
   ["typeDataQueueSize"]=18,
   ["constDataNumLoops"]=1000,
   ["constControlNumLoops"]=1000000,
   ["constControlSamplePc"]=30,
   ["constDataSamplePc"]=10
}


-- Kinds of stats exported by control thread
-- queue rate of flow updated to xx
-- first packet of flow sent with yy packets to go
-- fin packet of flow sent with 0 packets to go
-- fin packet of flow received with xx packets
-- Kinds of stats exported by application thread
-- flow started
-- number of active flows
-- flow ended

-- Kind of stats exported by data thread
-- try nothing
-- throughput at NIC
-- queue size at NIC

ffi.cdef[[
typedef struct {
 double d1, d2; 
 int i1, i2; 
 int i3;
 double time;
 int loop;
 int valid, msgType;
} genericMsg;
typedef genericMsg* pGenericMsg;
// type 1: data tx throughput where d1 = throughput
// type 2: data rx throughput where d1 = throughput
// type 3: data tx queue throughput where d1 = throughput, i1 = queue
// type 4: data rx queue throughput where d1 = throughput, i1 = queue
// type 5: data tx queue size where i1 = queue size, i2 = queue
// type 6: data rx queue size where i1 = queue size, i2 = queue
// type 7: app active flows where i1 = number of active flows
// type 8: control rate where d1 = rate, i1 = flow
// type 9: data rate where d1 = rate, i1 = flow
]]

function monitorMod.acceptMsgs(pipes, pipeName, waitxTenUs)
   return ipcMod.fastAcceptMsgs(pipes, pipeName, "pGenericMsg", waitxTenUs)
end

-- example use .. pipe:send(ffi.new("pGenericMsg",
--  {[i1]: xx, [d1]: xx, [valid]: 1234, [type]: , [time]: time})
   
function monitorMod.getPerVmPipes(devNoList)
   local pipes = {}
   for i,devNo in ipairs(devNoList) do
      pipes["control-"..devNo] = pipe.newFastPipe(20)
      pipes["data-"..devNo] = pipe.newFastPipe(20)
      pipes["app-"..devNo] = pipe.newFastPipe(20)     
   end
   for pipeName, pipe in pairs(pipes) do
      print("Return " .. pipeName)
   end
   return pipes
end

function  monitorMod.monitorSlave(pipes, readyInfo)
   local thisCore = dpdk.getCore()
   print("Running monitor slave on core " .. thisCore)   
   ipc.waitTillReady(readyInfo)

   local logFiles = {}
   for pipeName, pipe in pairs(pipes) do
      logFiles[pipeName] = io.open(pipeName.. "-log.txt", "w")
   end
   
   while dpdk.running() do
      --local pipeName = "control-0"
      --local logFile = logFiles[pipeName]
      for pipeName, logFile in pairs(logFiles) do
	 msgs = monitorMod.acceptMsgs(pipes, pipeName, 10)
	 if (msgs ~= nil) then
	    for msgNo, msg in pairs(msgs) do
	       local line = monitorMod.format(msg)
	       --print("writing " .. line .. " to file for " .. pipeName)
	       if line == nil then print("unrecognized msg of type " .. msg.msgType .. " on " .. pipeName)
	       else logFile:write(line) end
	    end
	    --end
	 end
      end
   end
end

function monitorMod.format(msg)
   local msg = ffi.cast("pGenericMsg", msg)
   -- TODO(lav): array of handlers instead of if else ..
   if msg.msgType == monitorMod.typeDataTxMbps then
      return ("tx_throughput_mbps " .. msg.d1 .. "\n")
   elseif msg.msgType == monitorMod.typeNumActiveQueues then
      return("app_active_queues time_num "
		.. msg.time
		.. " " .. msg.i1
		.. "\n")
   elseif msg.msgType == monitorMod.typeControlPacketRtt then
      return("control_packet_rtt time_rttus "
		.. msg.time
		.. " " .. msg.i1
		.. "\n")
   elseif msg.msgType == monitorMod.typeAppActiveFlowsNum then
      return("app_active_flows time_num "
		.. msg.time
		.. " " .. msg.i1
		.. "\n")
   elseif msg.msgType == monitorMod.typeFlowTxRateConfigured then
      return("flow_tx_rate_configured "
		.. "loop_time_flow_configured_actual "
		.. msg.loop
		.. " " .. msg.time 
		.. " " .. msg.i1
		.. " " .. msg.d1
		.. " " .. msg.d2
		.. "\n")
   elseif msg.msgType == monitorMod.typeSetFlowTxRate then 
      return("set_flow_tx_rate "
		.. "loop_time_flow_rate "
		.. msg.loop
		.. " " .. msg.time
		.. " " .. msg.i1
		.. " " .. msg.d1 .. "\n")
   elseif msg.msgType == monitorMod.typeGetFlowBottleneckRate then      
      return("get_flow_bottleneck_rate "
		.. "loop_time_flow_rate "
		.. msg.loop
		.. " " .. msg.time
		.. " " .. msg.i1
		.. " " .. msg.d1 .. "\n")
   elseif msg.msgType == monitorMod.typeControlDpdkLoopStartTime then      
      return("control_dpdk_loop_start_time "
		.. "time_num "
		..  msg.time
		.. " " .. msg.i1
		.. "\n")
   elseif msg.msgType == monitorMod.typeCorruptedDataPkts then      
      return("corrupted_data_pkts "
		.. "time_num "
		..  msg.time
		.. " " .. msg.i1
		.. "\n")
   elseif msg.msgType == monitorMod.typeFlowFctLoss then      
      return("flow_fct_loss "
		.. "time_flow_fct_fct_loss_total "
		..  msg.time
		.." " .. msg.i1	     
		.. " " .. msg.d1
		.. "us " .. msg.d2
		.. "us " .. msg.i2
		.. "% " .. msg.loop
		.. "\n")
   elseif msg.msgType == monitorMod.typeDataQueueSize then
      local wantedToSend = msg.d2
      local sent = msg.d1
      local queueSizeValid = 0
      local queueSize = 0
      local maxSize = perc_constants.NIC_DESCRIPTORS_PER_QUEUE
      -- TODO(lav): check this is right .. btw it's possible
      -- that wantedToSend = send = 128 while maxSize only 40
      -- queueing only when oversubscribed!
      if (sent < wantedToSend) then
	 queueSize = wantedToSend - sent
	 if queueSize > maxSize then queueSize = maxSize end
	 -- all unsent packets are dropped either way ^
	 -- sent equals number of packets ever put on queue
	 -- including those serviced and those currently enqueued
	 queueSizeValid = 1
	 end
            
      return("data_queue_size time_queue_flow_sent_total_sizevalid_size "
		.. msg.time
		.. " " .. msg.i1
		.. " " .. msg.i2
		.. " " .. sent
		.. " " .. wantedToSend
		.. " " .. queueSizeValid
		.. " " .. queueSize
		.. "\n")
   elseif msg.msgType == monitorMod.typeDataStatsPerDpdkLoop then
      local numLoops = monitorMod.constDataNumLoops * 1.0

      local runtime = msg.d1

      local txDataPackets = msg.d2
      local txAckPackets = msg.i2
      local rxDataPackets = msg.i1
      local rxAckPackets = msg.loop
      
      local txDataBytes = txDataPackets*perc_constants.DATA_PACKET_SIZE
      local txAckBytes = txAckPackets*perc_constants.ACK_PACKET_SIZE
      local txTotalBytes =  txDataBytes + txAckBytes
	 
      local rxDataBytes = rxDataPackets*perc_constants.DATA_PACKET_SIZE 
      local rxAckBytes = rxAckPackets*perc_constants.ACK_PACKET_SIZE
      local rxTotalBytes = rxDataBytes + rxAckBytes

      local txDataThroughput = (8.0*txDataBytes)/runtime
      local txAckThroughput = (8.0*txAckBytes)/runtime      
      local txTotalThroughput = txDataThroughput + txAckThroughput

      local rxDataThroughput = (8.0*rxDataBytes)/runtime
      local rxAckThroughput = (8.0*rxAckBytes)/runtime      
      local rxTotalThroughput = rxDataThroughput + rxAckThroughput


      local line1 = ("data_stats_per_dpdk_loop_raw "
			.. "time_runtimeus_txdatapkts_rxdatapkts_txackpkts_rxackpkts "
			..  msg.time
			.." " .. (runtime * (1e6/numLoops))
			.. " " .. (txDataPackets/numLoops)
			.. " " .. (rxDataPackets/numLoops)
			.. " " .. (txAckPackets/numLoops)
		     	.. " " .. (rxAckPackets/numLoops))


      local line2 =  ("data_stats_per_dpdk_loop_processed_tx "
			.. "time_txdatabytes_txackbytes_txtotalbytes_txdatabps_txackbps_txtotalbps "
			..  msg.time
			 .." " .. (txDataBytes/numLoops)
			 .. " " .. (txAckBytes/numLoops)
			 .. " " .. (txTotalBytes/numLoops)
			 .. " " .. (txDataThroughput)
			 .. " " .. (txAckThroughput)
			 .. " " .. (txTotalThroughput))

      local line3 =  ("data_stats_per_dpdk_loop_processed_rx "
			 .. "time_rxdatabytes_rxackbytes_rxtotalbytes_rxdatabps_rxackbps_rxtotalbps "
			 ..  msg.time
			 .." " .. (rxDataBytes/numLoops)
			 .. " " .. (rxAckBytes/numLoops)
			 .. " " .. (rxTotalBytes/numLoops)
			 .. " " .. (rxDataThroughput)
			 .. " " .. (rxAckThroughput)
			 .. " " .. (rxTotalThroughput))

      return (line1 .. "\n" .. line2 .. "\n"..  line3 .. "\n")
   elseif msg.msgType == monitorMod.typeControlStatsPerDpdkLoop then
      local numLoops = monitorMod.constControlNumLoops * 1.0

      local runtime = msg.d1

      local txNewControlPackets = msg.d2
      local txOngoingControlPackets = msg.i1
      local rxControlPackets = msg.i2
      
      local txNewControlBytes = txNewControlPackets*perc_constants.CONTROL_PACKET_SIZE
      local txOngoingControlBytes = txOngoingControlPackets*perc_constants.CONTROL_PACKET_SIZE
      local txTotalBytes =  txNewControlBytes + txOngoingControlBytes
	 
      local rxControlBytes = rxControlPackets*perc_constants.CONTROL_PACKET_SIZE 
      local rxTotalBytes = rxControlBytes

      local txNewControlThroughput = (8.0*txNewControlBytes)/runtime
      local txOngoingControlThroughput = (8.0*txOngoingControlBytes)/runtime      
      local txTotalThroughput = txNewControlThroughput + txOngoingControlThroughput

      local rxControlThroughput = (8.0*rxControlBytes)/runtime
      local rxTotalThroughput = rxControlThroughput


      local line1 = ("control_stats_per_dpdk_loop_raw "
			.. "time_runtimeus_txnewcontrolpkts_txongoingcontrolpkts_rxcontrolpkts "
			..  msg.time
			.." " .. (runtime * (1e6/numLoops))
			.. " " .. (txNewControlPackets/numLoops)
			.. " " .. (txOngoingControlPackets/numLoops)
			.. " " .. (rxControlPackets/numLoops))

      local line2 =  ("control_stats_per_dpdk_loop_processed_tx "
			.. "time_txnewcontrolbytes_txongoingcontrolbytes_txtotalbytes_txnewcontrolbps_txongoingcontrolbps_txtotalbps "
			..  msg.time
			 .." " .. (txNewControlBytes/numLoops)
			 .. " " .. (txOngoingControlBytes/numLoops)
			 .. " " .. (txTotalBytes/numLoops)
			 .. " " .. (txNewControlThroughput)
			 .. " " .. (txOngoingControlThroughput)
			 .. " " .. (txTotalThroughput))

      local line3 =  ("control_stats_per_dpdk_loop_processed_rx "
			 .. "time_rxcontrolbytes_rxcontrolbps "
			 ..  msg.time
			 .." " .. (rxControlBytes/numLoops)
			 .. " " .. (rxControlThroughput))
      
      return (line1 .. "\n" .. line2 .. "\n"..  line3 .. "\n")
   else            
      return nil
   end
end
   
return monitorMod
