-- Wireshark dissector for Arista Networks Ethertype (ethertype == 0x2d8b)
-- Header is inserted after the Source Address field
-- Header format for TapAgg Timestamps
-- ------------------------------------------------------
-- |EtherType (2)|Sub-type (2)|Version (2)|Timestamp (8)|
-- ------------------------------------------------------

Arista = Proto ("arista", "Arista Networks")
local a_proto = DissectorTable.new("arista", "Arista Networks")
TapaggTimestamp = Proto ("arista.tapaggtimestamp", "TapAgg Header Timestamp")
UnknownSubtype = Proto ("arista.unknown", "Unknown Subtype")
-- Arista Registered Ethertype
local arista_ethertype = 0xd28b
-- Subtype for TapAgg timestamp
local tapagg_timestamp = 0x1
local etypetable = DissectorTable.get("ethertype")

-- Under single Ethertype we can support multiple subtypes
local a_subtype = ProtoField.protocol ("arista.subtype", "Arista Subtype")
Arista.fields = { a_subtype }

-- TapAgg Timestamp Header has a version number and a timestamp
local t_version = ProtoField.uint16 ("arista.timestamp.version", "Version", base.HEX)
local t_ts = ProtoField.absolute_time("arista.tapaggtimestamp.timestamp", "Timestamp")
local t_comment = ProtoField.string("multi.text", "Comment")
TapaggTimestamp.fields = { t_version, t_ts, t_comment }

-- Dissector for the Arista EtherType
function Arista.dissector(buf, packet, tree)
  -- look at subtype
  local p = buf(0,2):uint()
  local pos=2
  -- check if it is a timestamp
  if p == tapagg_timestamp then
     local subtree = tree:add(Arista, buf(0,12), "Arista Networks")
     arista_table = DissectorTable.get ("arista")
     -- tapagg timestamp has version and 8 byte timestamp
     -- load the timestamp dissector
     arista_table:add (tapagg_timestamp, TapaggTimestamp)
     local dissect = a_proto:get_dissector(p)
     pos = pos + dissect:call(buf(2):tvb(), packet, subtree)
     -- Dissect the original packet
     -- Original type field
     local next_type = buf(pos,2):uint()
     -- Get the dissector for that type
     local d = etypetable:get_dissector(next_type)

     -- Verify that Wireshark understands it
     if d then
      pos=pos+2
      d:call(buf:range(pos):tvb(), packet, tree)
     else
      Dissector.get("ethertype"):call(buf:range(pos):tvb(),packet,tree)
     end

    -- other subtypes as they are defined
    -- only timestamp subtype defined today
    else
     -- Unknown subtype
     local subtree = tree:add(Arista, buf(0,2), "Arista")
     arista_table = DissectorTable.get ("arista")
     arista_table:add(p, UnknownSubtype)
     local dissect = a_proto:get_dissector(p)
     pos = pos + dissect:call(buf(2):tvb(), packet, subtree)
    end
    return pos
end

function TapaggTimestamp.dissector(buf, packet, tree)
    local t = tree:add (TapaggTimestamp, buf(0,10))
    local v = t:add(t_version, buf(0,2))
    local sec_len = 4
    -- 48b timestamp has 2 bytes seconds
    version = buf(0,2):uint()
    -- reserve lower 4 bits in version field for hw info
    version = bit32.band( version, 0xfff0 )
    if version == 0x20 then
       sec_len = 2
    end
    local seconds = buf(2,sec_len):uint()
    -- 4 bytes for nanoseconds
    ns_offset = 2 + sec_len
    local nanoseconds = buf(ns_offset,4):uint()
    -- add the raw timestamp the info column
    packet.cols.info = "TapAgg Timestamp: " .. seconds.."."..nanoseconds .. " "
    packet.cols.info:fence()
    -- in the packet tree view show the time as a string
    -- compensate 48b timestamp seconds with local time upper 16b
    if sec_len == 2 then
     local packet_seconds, packet_ns = math.modf(packet.abs_ts)
     local epoch_seconds = bit32.replace(packet_seconds, seconds, 0, 16)
     seconds = epoch_seconds
    end
    local time = NSTime.new(seconds, nanoseconds)
    buf_len = sec_len + 4
    local ts = t:add(t_ts, buf(2,buf_len), time)
    if sec_len == 2 then
     local comment = t:add(t_comment, "For 48b timestamp, extra MSB 16b will be extracted from local packet capture time to display a full 64b timestamp here")
    end
    return buf_len + 2
end

function UnknownSubtype.dissector(buf, packet, tree)
    -- if we don't recognize the subtype, we don't know where the original
    -- packet starts
    local u = tree:add(UnknownSubtype, buf(0,2))
    return 2
end

etypetable:add(arista_ethertype, Arista)
