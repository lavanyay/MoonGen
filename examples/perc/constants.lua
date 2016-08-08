constantsMod = {
   ["CONTROL_PACKET_SIZE"] = 128,
   -- 11B b/n control and host state, 6 b/n .. agg 80
   ["DATA_PACKET_SIZE"] = 1500,
   ["ACK_PACKET_SIZE"] = 128,
   ["DATA_RXQUEUE"] = 4,
   ["CONTROL_QUEUE"] = 1,
   ["ACK_QUEUE"] = 2,
   ["DROP_QUEUE"] = 3,
   ["ETHTYPE_ACK"] = 5678,
   ["ETHTYPE_DATA"] = 6789,
   ["LOG_EVERY_N_SECONDS"] = 1e-3,
   ["NEW_FLOWS_PER_CONTROL_LOOP"] = 2,
   ["NIC_DESCRIPTORS_PER_QUEUE"] = 40,  -- 82599 TODO(lav): indep. of pkt size, 1 / pkt
   ["LOG_DATA"] = false,
   ["LOG_CONTROL"] = false,
   ["LOG_APP"] = false
}

return constantsMod
