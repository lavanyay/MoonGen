---------------------------------
--- @file filter_ixgbe.lua
--- @brief Filter for IXGBE ...
--- @todo TODO docu
---------------------------------

local mod = {}

local dpdkc = require "dpdkc"
local device = require "device"
local ffi = require "ffi"
local dpdk = require "dpdk"
local mbitmask = require "bitmask"
local err = require "error"
local log = require "log"

local ETQF_BASE			= 0x00005128
local ETQS_BASE			= 0x0000EC00

local ETQF_FILTER_ENABLE	= bit.lshift(1, 31)
local ETQF_IEEE_1588_TIME_STAMP	= bit.lshift(1, 30)

local ETQS_RX_QUEUE_OFFS	= 16
local ETQS_QUEUE_ENABLE		= bit.lshift(1, 31)

local ETQF = {}
for i = 0, 7 do
	ETQF[i] = ETQF_BASE + 4 * i
end
local ETQS = {}
for i = 0, 7 do
	ETQS[i] = ETQS_BASE + 4 * i
end

-- from rte_eth_ctrl.h
-- TODO(lav): don't know how to use enums in Lua
local RTE_ETH_FILTER_FLUSH = 4
local RTE_ETH_FILTER_DELETE = 3
local RTE_ETH_FILTER_ADD = 1
local RTE_ETH_FILTER_NTUPLE = 5
local RTE_ETH_FILTER_ETHERTYPE = 2
local RTE_ETH_FILTER_FDIR = 7

local RTE_NTUPLE_FLAGS_DST_IP    = 0x0001
local RTE_NTUPLE_FLAGS_SRC_IP    = 0x0002
local RTE_NTUPLE_FLAGS_DST_PORT  = 0x0004
local RTE_NTUPLE_FLAGS_SRC_PORT  = 0x0008
local RTE_NTUPLE_FLAGS_PROTO     = 0x0010
local RTE_NTUPLE_FLAGS_TCP_FLAG  = 0x0020
local RTE_5TUPLE_FLAGS = bit.bor(RTE_NTUPLE_FLAGS_DST_IP,  RTE_NTUPLE_FLAGS_SRC_IP,   RTE_NTUPLE_FLAGS_DST_PORT,   RTE_NTUPLE_FLAGS_SRC_PORT,   RTE_NTUPLE_FLAGS_PROTO)

local RTE_ETHTYPE_FLAGS_MAC    = 0x0001 -- If set, compare mac
local RTE_ETHTYPE_FLAGS_DROP   = 0x0002 -- If set, drop packet when match

ffi.cdef[[
//ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */

/**
 * Ethernet address:
 * A universally administered address is uniquely assigned to a device by its
 * manufacturer. The first three octets (in transmission order) contain the
 * Organizationally Unique Identifier (OUI). The following three (MAC-48 and
 * EUI-48) octets are assigned by that organization with the only constraint
 * of uniqueness.
 * A locally administered address is assigned to a device by a network
 * administrator and does not contain OUIs.
 * See http://standards.ieee.org/regauth/groupmac/tutorial.html
 */
struct ether_addr {
    uint8_t addr_bytes[6]; /**< Address bytes in transmission order */
} __attribute__((__packed__));

/**
 * A structure used to define the ethertype filter entry
 * to support RTE_ETH_FILTER_ETHERTYPE with RTE_ETH_FILTER_ADD,
 * RTE_ETH_FILTER_DELETE and RTE_ETH_FILTER_GET operations.
 *struct rte_eth_ethertype_filter {
 *   struct ether_addr mac_addr;   < Mac address to match. 
 *   uint16_t ether_type;          < Ether type to match 
 *   uint16_t flags;               < Flags from RTE_ETHTYPE_FLAGS_
 *   uint16_t queue;               < Queue assigned to when match
 * };
*/

/**
 * A structure used to define the ntuple filter entry
 * to support RTE_ETH_FILTER_NTUPLE with RTE_ETH_FILTER_ADD,
 * RTE_ETH_FILTER_DELETE and RTE_ETH_FILTER_GET operations.
 */
struct rte_eth_ntuple_filter {
    uint16_t flags;          /**< Flags from RTE_NTUPLE_FLAGS_* */
    uint32_t dst_ip;         /**< Destination IP address in big endian. */
    uint32_t dst_ip_mask;    /**< Mask of destination IP address. */
    uint32_t src_ip;         /**< Source IP address in big endian. */
    uint32_t src_ip_mask;    /**< Mask of destination IP address. */
    uint16_t dst_port;       /**< Destination port in big endian. */
    uint16_t dst_port_mask;  /**< Mask of destination port. */
    uint16_t src_port;       /**< Source Port in big endian. */
    uint16_t src_port_mask;  /**< Mask of source port. */
    uint8_t proto;           /**< L4 protocol. */
    uint8_t proto_mask;      /**< Mask of L4 protocol. */
    /** tcp_flags only meaningful when the proto is TCP.
        The packet matched above ntuple fields and contain
        any set bit in tcp_flags will hit this filter. */
    uint8_t tcp_flags;
    uint16_t priority;       /**< seven levels (001b-111b), 111b is highest,
                      used when more than one filter matches. */
    uint16_t queue;          /**< Queue assigned to when match*/
};

// defined in lib/librte_ether/rte_eth_ctrl.h
int rte_eth_dev_filter_ctrl( 	uint8_t  	port_id,
                enum rte_filter_type filter_type,
                enum rte_filter_op filter_op,
                void * arg);

// deprecated
int rte_eth_dev_add_5tuple_filter 	( 	uint8_t  	port_id,
		uint16_t  	index,
		struct rte_5tuple_filter *  	filter,
		uint16_t  	rx_queue 
	);
int
mg_5tuple_add_HWfilter_ixgbe(uint8_t port_id, uint16_t index,
			struct rte_5tuple_filter *filter, uint16_t rx_queue);
]]

function mod.l2Filter(dev, etype, queue)
	if queue == -1 then
		queue = 127
	end
	dpdkc.write_reg32(dev.id, ETQF[1], bit.bor(ETQF_FILTER_ENABLE, etype))
	dpdkc.write_reg32(dev.id, ETQS[1], bit.bor(ETQS_QUEUE_ENABLE, bit.lshift(queue, ETQS_RX_QUEUE_OFFS)))
end

function mod.flushHWFilter(dev)
   local state =
      ffi.C.rte_eth_dev_filter_ctrl(dev.id, RTE_ETH_FILTER_FDIR,
				    RTE_ETH_FILTER_FLUSH, NULL)
  if (state ~= 0) then
     log:fatal("Flow Directory entries not successfully flushed: %s", err.getstr(-state))
  end
end   
--- Installs an Ethertype filter on the device.
---  Matching packets will be redirected into the specified rx queue
--- @param filter A table describing the filter. Possible fields are
---   ether_type    :  Ether type to match
---  All fields are optional.
---  If a field is not present, or nil, the filter will ignore this field when
---  checking for a match.
--- @param queue RX Queue, where packets, matching this filter will be redirected
function mod.addHWEthertypeFilter(dev, filter, queue)
   local sfilter = ffi.new("struct rte_eth_ethertype_filter")
   -- TODO(lav): sfilter.mac_addr zeroe-d out by default ?

   
   sfilter.ether_type   = filter.ether_type
   if (filter.ether_type == nil) then sfilter.ether_type = 0 end   
   sfilter.flags = 0 -- won't compare MC, won't drop
   sfilter.queue = queue
   if (queue == nil) then sfilter.queue = 0 end
  
  if dev.filtersEthertype == nil then
    dev.filtersEthertype = {}
    dev.filtersEthertype.n = 0
  end
  dev.filtersEthertype[dev.filtersEthertype.n] = sfilter
  local idx = dev.filtersEthertype.n
  dev.filtersEthertype.n = dev.filtersEthertype.n + 1

  local state
  if (dev:getPciId() == device.PCI_ID_X540) then
    -- TODO: write a proper patch for dpdk
    state = ffi.C.mg_5tuple_add_HWfilter_ixgbe(dev.id, idx, sfilter, queue.qid)
  else
     --state = ffi.C.rte_eth_dev_add_5tuple_filter(dev.id, idx, sfilter, queue.qid)
     print("ether_type is " .. sfilter.ether_type .. " and queue is "
	      .. sfilter.queue)

     state = ffi.C.rte_eth_dev_filter_ctrl(dev.id, RTE_ETH_FILTER_ETHERTYPE,
					   RTE_ETH_FILTER_ADD, sfilter)
  end

  
  if (state ~= 0) then
     log:fatal("Filter not successfully added: %s", err.getstr(-state))
  end

  return idx
end

--- Installs a 5tuple filter on the device.
---  Matching packets will be redirected into the specified rx queue
---  NOTE: this is currently only tested for X540 NICs, and will probably also
---  work for 82599 and other ixgbe NICs. Use on other NICs might result in
---  undefined behavior.
--- @param filter A table describing the filter. Possible fields are
---   src_ip    :  Sourche IPv4 Address
---   dst_ip    :  Destination IPv4 Address
---   src_port  :  Source L4 port
---   dst_port  :  Destination L4 port
---   l4protocol:  L4 Protocol type
---                supported protocols: ip.PROTO_ICMP, ip.PROTO_TCP, ip.PROTO_UDP
---                If a non supported type is given, the filter will only match on
---                protocols, which are not supported.
---  All fields are optional.
---  If a field is not present, or nil, the filter will ignore this field when
---  checking for a match.
--- @param queue RX Queue, where packets, matching this filter will be redirected
--- @param priority optional (default = 1) The priority of this filter rule.
---  7 is the highest priority and 1 the lowest priority.
function mod.addHW5tupleFilter(dev, filter, queue, priority)
   local sfilter = ffi.new("struct rte_eth_ntuple_filter")
  sfilter.src_ip_mask   = (filter.src_ip      == nil) and 1 or 0
  sfilter.dst_ip_mask   = (filter.dst_ip      == nil) and 1 or 0
  sfilter.src_port_mask = (filter.src_port    == nil) and 1 or 0
  sfilter.dst_port_mask = (filter.dst_port    == nil) and 1 or 0
  sfilter.proto_mask = (filter.l4protocol  == nil) and 1 or 0

  sfilter.priority = 1 --priority or 1
  if(sfilter.priority > 7 or sfilter.priority < 1) then
    log:fatal("Filter priority has to be a number from 1 to 7")
    return
  end

  sfilter.src_ip    = filter.src_ip     or 0
  sfilter.dst_ip    = filter.dst_ip     or 0
  sfilter.src_port  = filter.src_port   or 0
  sfilter.dst_port  = filter.dst_port   or 0
  sfilter.proto  = filter.l4protocol or 0
  sfilter.tcp_flags = filter.tcp_flags or 0
  --if (filter.l4protocol) then
  --  print "[WARNING] Protocol filter not yet fully implemented and tested"
  --end

  sfilter.queue = 0 --queue or 0
  sfilter.flags = RTE_5TUPLE_FLAGS
  
  if dev.filters5Tuple == nil then
    dev.filters5Tuple = {}
    dev.filters5Tuple.n = 0
  end
  dev.filters5Tuple[dev.filters5Tuple.n] = sfilter
  local idx = dev.filters5Tuple.n
  dev.filters5Tuple.n = dev.filters5Tuple.n + 1

  local state
  if (dev:getPciId() == device.PCI_ID_X540) then
    -- TODO: write a proper patch for dpdk
    state = ffi.C.mg_5tuple_add_HWfilter_ixgbe(dev.id, idx, sfilter, queue.qid)
  else
     --state = ffi.C.rte_eth_dev_add_5tuple_filter(dev.id, idx, sfilter, queue.qid)
     state = ffi.C.rte_eth_dev_filter_ctrl(dev.id, RTE_ETH_FILTER_NTUPLE,
					   RTE_ETH_FILTER_ADD, sfilter)
  end

  if (state ~= 0) then
    log:fatal("Filter not successfully added: %s", err.getstr(-state))
  end

  return idx
end

return mod
