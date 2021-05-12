-- @brief Synology Finder Protocol(9999/udp) Dissector Plugin
-- @author cq674350529

-- reference:
--  1) https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
--  2) https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-cdp.c
--  3) https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html
--  4) https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html

local synoFinderProtocol = Proto("SynoFinder", "Synology Finder Protocol")
local protoName = "syno_finder"

local typeNames = {
    [0x1] = "Packet Type",
    [0x11] = "Server Name",
    [0x12] = "IP",
    [0x13] = "Subnet Mask",
    [0x14] = "DNS",
    [0x15] = "DNS",
    [0x19] = "Mac Address",
    [0x1e] = "Gateway",
    [0x20] = "Packet Subtype",
    [0x21] = "Server Name",
    [0x29] = "Mac Address",
    [0x2a] = "Password",
    [0x49] = "Build Num",
    [0x4a] = "Username",
    [0x4b] = "Share Folder",
    [0x70] = "Unique",
    [0x71] = "Support Raid",
    [0x73] = "Serial Num",
    [0x75] = "Port",
    [0x76] = "Ssl Port",
    [0x77] = "Product Version",
    [0x78] = "Model",
    [0x79] = "Memtest Error Code",
    [0x7c] = "Mac Address",
    [0x90] = "Small Fix Num",
    [0xc0] = "Serial Num",
    [0xc1] = "Os Name",
    [0xc3] = "Support Onsite Tool",
    [0xc4] = "Public Key",
    [0xc5] = "Random Bytes"
}

local magic = ProtoField.bytes(protoName .. ".magic", "Magic", base.SPACE)

-- subtree header
local tlv = ProtoField.bytes(protoName .. "tlv", "TLV")     -- only used to group type, length and value
local type = ProtoField.uint8(protoName .. ".type", "Type", base.HEX, typeNames)
local length = ProtoField.uint8(protoName .. ".length", "Length")
local value = ProtoField.bytes(protoName .. ".value", "Value")

-- specific value field
local packetType = ProtoField.uint32(protoName .. ".packet_type", "Packet Type", base.HEX)
local serverName = ProtoField.string(protoName .. ".server_name", "Server Name")
local ipAddress = ProtoField.ipv4(protoName .. ".ip_address", "IP")
local ipMask = ProtoField.ipv4(protoName .. ".subnet_mask", "Subnet Mask")
local dns = ProtoField.ipv4(protoName .. ".dns", "DNS")
local macAddress = ProtoField.string(protoName .. ".mac_address", "Mac Address")
local ipGateway = ProtoField.ipv4(protoName .. ".gateway", "Gateway")
local packetSubtype = ProtoField.uint32(protoName .. ".packet_subtype", "Packet Subtype", base.HEX)
local password = ProtoField.string(protoName .. ".password", "Password")
local buildNum = ProtoField.uint32(protoName .. ".build_num", "Build Num")
local unique = ProtoField.string(protoName .. ".unique", "Unique")
local supportRaid = ProtoField.uint32(protoName .. ".support_raid", "Support Raid")
local port = ProtoField.uint32(protoName .. ".port", "Port")
local sslPort = ProtoField.uint32(protoName .. ".ssl_port", "Ssl Port")
local username = ProtoField.string(protoName .. ".username", "Username")
local shareFolder = ProtoField.string(protoName .. ".share_folder", "Share Folder")
local productVersion = ProtoField.string(protoName .. ".product_version", "Product Version")
local model = ProtoField.string(protoName .. ".model", "Model")
local memtestErrorCode = ProtoField.uint32(protoName .. ".memtest_error_code", "Memtest Error Code", base.HEX)
local smallFixNum = ProtoField.uint32(protoName .. ".small_fix_num", "Small Fix Num")
local serialNum = ProtoField.string(protoName .. ".serial_num", "Serial Num")
local osName = ProtoField.string(protoName .. ".os_name", "Os Name")
local supportOnsiteTool = ProtoField.string(protoName .. ".support_onsite_tool", "Support Onsite Tool")
local publicKey = ProtoField.string(protoName .. ".public_key", "Public Key")
local randomBytes = ProtoField.uint32(protoName .. ".random_bytes", "Random Bytes", base.HEX)

local value8 = ProtoField.uint8(protoName .. ".value", "Value", base.HEX)
local value16 = ProtoField.uint16(protoName .. ".value", "Value", base.HEX)
local value32 = ProtoField.uint32(protoName .. ".value", "Value", base.HEX)

local typeFields = {
    [0x1] = packetType,
    [0x11] = serverName,
    [0x12] = ipAddress,
    [0x13] = ipMask,
    [0x14] = dns,
    [0x15] = dns,
    [0x19] = macAddress,
    [0x1e] = ipGateway,
    [0x20] = packetSubtype,
    [0x21] = serverName,
    [0x29] = macAddress,
    [0x2a] = password,
    [0x49] = buildNum,
    [0x4a] = username,
    [0x4b] = shareFolder,
    [0x70] = unique,
    [0x71] = supportRaid,
    [0x73] = serialNum,
    [0x75] = port,
    [0x76] = sslPort,
    [0x77] = productVersion,
    [0x78] = model,
    [0x79] = memtestErrorCode,
    [0x7c] = macAddress,
    [0x90] = smallFixNum,
    [0xc0] = serialNum,
    [0xc1] = osName,
    [0xc3] = supportOnsiteTool,
    [0xc4] = publicKey,
    [0xc5] = randomBytes
}

-- display in subtree header
-- reference: 
--   1) https://gist.github.com/FreeBirdLjj/6303864
--   2) https://blog.csdn.net/humanxing/article/details/42318213
function format_uint_le(value)
    return value:le_uint()
end

function format_uint_hex(value)
    return string.format("%#x", value:le_uint())
end

function format_uint_bool(value)
    local bool_value = "False"
    if value:le_uint() ~= 0 then
        bool_value = "True"
    end
    return bool_value
end

function format_string(value)
    return value:string()
end

function format_ipv4(value)
    return value:ipv4()
end

local typeFormats = {
    [0x1] = format_uint_hex,
    [0x11] = format_string,
    [0x12] = format_ipv4,   -- Address object
    [0x13] = format_ipv4,
    [0x14] = format_ipv4,
    [0x15] = format_ipv4,
    [0x19] = format_string,
    [0x1e] = format_ipv4,
    [0x20] = format_uint_hex,
    [0x21] = format_string,
    [0x29] = format_string,
    [0x2a] = format_string,
    [0x49] = format_uint_le,
    [0x4a] = format_string,
    [0x4b] = format_string,
    [0x70] = format_string,
    [0x71] = format_uint_bool,
    [0x73] = format_string,
    [0x75] = format_uint_le,
    [0x76] = format_uint_le,
    [0x77] = format_string,
    [0x78] = format_string,
    [0x79] = format_uint_hex,
    [0x7c] = format_string,
    [0x90] = format_uint_le,
    [0xc0] = format_string,
    [0xc1] = format_string,
    [0xc3] = format_uint_bool,
    [0xc4] = format_string,
    [0xc5] = format_uint_hex
}

-- register fields
synoFinderProtocol.fields = {
    magic,
    tlv, type, length, value,     -- tlv
    packetType, serverName, ipAddress, ipMask, ipGateway, macAddress, dns, packetSubtype, password, buildNum, unique, supportRaid, username, shareFolder, port, sslPort, productVersion, model, memtestErrorCode, smallFixNum, serialNum, osName, supportOnsiteTool, publicKey, randomBytes,       -- specific value field
    value8, value16, value32
}

-- reference: https://stackoverflow.com/questions/52012229/how-do-you-access-name-of-a-protofield-after-declaration
function getFieldName(field)
    local fieldString = tostring(field)
    local i, j = string.find(fieldString, ": .* " .. protoName)
    return string.sub(fieldString, i + 2, j - (1 + string.len(protoName)))
end

function getFieldType(field)
    local fieldString = tostring(field)
    local i, j = string.find(fieldString, "ftypes.* " .. "base")
    return string.sub(fieldString, i + 7, j - (1 + string.len("base")))
end

function getFieldByType(type, length)
    local tmp_field = typeFields[type]
    if(tmp_field) then
        return tmp_field    -- specific value filed
    else
        if length == 4 then     -- common value field
            return value32
        elseif length == 2 then
            return value16
        elseif length == 1 then
            return value8
        else
            return value
        end
    end
end

function formatValue(type, value)
    local tmp_func = typeFormats[type]
    if(tmp_func) then
        return tmp_func(value)
    else
        return ""
    end
end

-- reference: https://gist.github.com/yi/01e3ab762838d567e65d
function string_fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function synoFinderProtocol.dissector(buffer, pinfo, tree)
    -- (buffer: type Tvb, pinfo: type Pinfo, tree: type TreeItem)
    local buffer_length = buffer:len()
    if buffer_length == 0 then return end

    local magicValue = buffer(0, 8):string()
    local isEncrypt = 0
    if magicValue == string_fromhex("1234556653594e4f") then
        isEncrypt = 1
    elseif magicValue ~= string_fromhex("1234567853594e4f") then
        return
    end

    pinfo.cols.protocol = synoFinderProtocol.name

    local subtree = tree:add(synoFinderProtocol, buffer(), "Synology Finder Protocol")
    subtree:add_le(magic, buffer(0, 8))

    local offset = 0
    local payloadStart = 8
    if isEncrypt == 1 then
        -- just shows the raw encrypted data
        Dissector.get("data"):call(buffer(payloadStart+offset):tvb(), pinfo, subtree)
    else
        while payloadStart + offset < buffer_length do
            local tlvType = buffer(payloadStart + offset, 1):uint()
            local tlvLength = buffer(payloadStart + offset + 1, 1):uint()
            local valueContent = buffer(payloadStart + offset + 2, tlvLength)
            local tlvField = getFieldByType(tlvType, tlvLength)
            local fieldName = getFieldName(tlvField)
            local description
            if fieldName == "Value" then
                description = "TLV (type" .. ":" .. string.format("0x%x", tlvType) .. ")"
            else
                description = fieldName .. ": " .. tostring(formatValue(tlvType, valueContent))
            end

            -- reference: https://osqa-ask.wireshark.org/questions/42404/lua-dissector-tree-collapse/
            -- local tlvSubtree = subtree:add(synoFinderProtocol, buffer(payloadStart+offset, tlvLength+2), description)
            local tlvSubtree = subtree:add(tlv, buffer(payloadStart+offset, tlvLength+2)):set_text(description)
            tlvSubtree:add_le(type, buffer(payloadStart + offset, 1))
            tlvSubtree:add_le(length, buffer(payloadStart + offset + 1, 1))
            if tlvLength > 0 then
                local fieldType = getFieldType(tlvField)
                if string.find(fieldType, "^IP") == 1 then
                    -- start with "IP"
                    tlvSubtree:add(tlvField, buffer(payloadStart + offset + 2, tlvLength))
                else
                    tlvSubtree:add_le(tlvField, buffer(payloadStart + offset + 2, tlvLength))
                end
            end

            offset = offset + 2 + tlvLength
        end

        if payloadStart + offset ~= buffer_length then
            -- fallback dissector that just shows the raw data
            Dissector.get("data"):call(buffer(payloadStart+offset):tvb(), pinfo, tree)
        end
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, synoFinderProtocol)      -- udp broadcast port
