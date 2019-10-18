-- Wireshark dissector for Arista Networks GRE TYPE (gre_type == 0x2d8b)
-- Header is inserted after the Source Address field
-- Header format for TapAgg Timestamps
-- ------------------------------------------------------
-- |Sub-Type (2)|Sub-version (2)|Seconds (2)|Nanosec (6)|
-- ------------------------------------------------------

Arista = Proto ("arista", "Arista Networks")
local a_proto = DissectorTable.new("arista", "Arista Networks")
TapaggTimestamp = Proto ("arista.tapaggtimestamp", "TapAgg Header Timestamp")
UnknownSubtype = Proto ("arista.unknown", "Unknown Subtype")
-- Arista Registered Ethertype
local arista_greproto = 0xd28b
-- Subtype for TapAgg timestamp
local tapagg_timestamp = 0x3

-- Under single Ethertype we can support multiple subtypes
local a_subtype = ProtoField.protocol ("arista.subtype", "Arista Subtype")
Arista.fields = { a_subtype }

-- TapAgg Timestamp Header has a version number and a timestamp
local t_version = ProtoField.uint16 ("arista.timestamp.version", "Version", base.HEX)
local t_sessionid = ProtoField.uint16 ("arista.timestamp.sessionid", "Session ID", base.HEX)
local t_seconds = ProtoField.uint16 ("arista.timestamp.seconds", "Seconds")
local t_nanoseconds = ProtoField.uint32 ("arista.timestamp.nanoseconds", "Nanoseconds")
TapaggTimestamp.fields = { t_version, t_sessionid, t_seconds, t_nanoseconds }

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
     local next_type = 2048
     -- Get the dissector for that type
     local d = ether_table:get_dissector(next_type)

     -- Verify that Wireshark understands it
     if d then
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
     pos = pos + dissect:call(buf(12):tvb(), packet, subtree)
    end
    return pos
end

function TapaggTimestamp.dissector(buf, packet, tree)
    local t = tree:add (TapaggTimestamp, buf(0,10))
    local v = t:add(t_version, buf(0,2))
    local s = t:add(t_sessionid, buf(2,2))
    local sec = t:add(t_seconds, buf(4,2))
    local nsec = t:add(t_nanoseconds, buf(6,4))
    return 10
end

function UnknownSubtype.dissector(buf, packet, tree)
    -- if we don't recognize the subtype, we don't know where the original
    -- packet starts
    local u = tree:add(UnknownSubtype, buf(0,2))
    return 3
end

function Arista.init()
end

ether_table = DissectorTable.get ("gre.proto")
ether_table:add (arista_greproto, Arista)
