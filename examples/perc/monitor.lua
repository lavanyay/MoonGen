local ffi = require("ffi")
local dpdk	= require "dpdk"
local ipc = require "examples.perc.ipc"
local pipe		= require "pipe"

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
   else      
      return nil
   end
end
   
return monitorMod
