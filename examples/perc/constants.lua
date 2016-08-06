constantsMod = {
   ["CONTROL_PACKET_SIZE"] = 80,
   -- 11B b/n control and host state, 6 b/n .. agg 80
   ["DATA_PACKET_SIZE"] = 1500,
   ["ACK_PACKET_SIZE"] = 128,
   ["DATA_RXQUEUE"] = 0,
   ["CONTROL_QUEUE"] = 1,
   ["ACK_QUEUE"] = 2,
   ["DROP_QUEUE"] = 3,
   ["ETHTYPE_ACK"] = 5678,
   ["ETHTYPE_DATA"] = 6789,
   ["LOG_EVERY_N_SECONDS"] = 1e-3,
   ["NEW_FLOWS_PER_CONTROL_LOOP"] = 2, 
   ["LOG_DATA"] = false,
   ["LOG_CONTROL"] = false,
   ["LOG_APP"] = false
}

return constantsMod
