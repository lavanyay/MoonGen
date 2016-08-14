constantsMod = {
   ["CONTROL_PACKET_SIZE"] = 128,
   -- 11B b/n control and host state, 6 b/n .. agg 80
   ["DATA_PACKET_SIZE"] = 1500,
   ["ACK_PACKET_SIZE"] = 256,
   ["DATA_RXQUEUE"] = 0,
   ["CONTROL_TXQUEUE"] = 1,
   ["CONTROL_RXQUEUE"] = 1,
   ["ACK_RXQUEUE"] = 2,
   ["ACK_TXQUEUE"] = 2,
   ["DROP_QUEUE"] = 3,
   ["ETHTYPE_ACK"] = 5678,
   ["ETHTYPE_DATA"] = 6789,
   ["MAX_QUEUES"] = 30,
   ["tx_ack_timeout"] = 0.5,
   ["rx_ack_timeout"] = 0.1,
   ["LOG_EVERY_N_SECONDS"] = 1e-3,
   ["NEW_FLOWS_PER_CONTROL_LOOP"] = 2,
   ["NIC_DESCRIPTORS_PER_QUEUE"] = 40,  -- 82599 TODO(lav): indep. of pkt size, 1 / pkt
   ["WARN_DATA"] = true,
   ["LOG_RXDATA"] = true,
   ["LOG_TXDATA"] = false,
   ["LOG_CONTROL"] = false,
   ["LOG_APP"] = false
}

return constantsMod
