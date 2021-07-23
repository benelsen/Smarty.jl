module Smarty

using Dates, Parameters, TimeZones, Logging
export EncryptedPacket, DecryptedPacket, ParsedPacket, parse_telegram, decrypt_smarty_packet, encrypt_smarty_packet

include("utils.jl")
include("encryption.jl")

abstract type AbstractDataPoint end

struct UnknownData <: AbstractDataPoint
    obis
    values
end

struct ManufacturerFlagIdentifier <: AbstractDataPoint
    id
end

struct ManufacturerTypeIdentifier <: AbstractDataPoint
    id
end

struct Version <: AbstractDataPoint
    obis
    version
end

struct Timestamp <: AbstractDataPoint
    obis
    datetime
    isdst
end

struct ElectricityEnergyMeterReading <: AbstractDataPoint
    obis
    kind
    direction
    tariff
    value
    unit
end

struct ElectricityPowerMeterReading <: AbstractDataPoint
    obis
    kind
    direction
    tariff
    value
    unit
end

struct TariffIndicator <: AbstractDataPoint
    obis
    tariff
end

struct EquipmentName <: AbstractDataPoint
    obis
    name
end

struct PowerFailureCount <: AbstractDataPoint
    obis
    kind
    count
end

struct PowerFailureLog <: AbstractDataPoint
    obis
    events
end

struct PowerFailure <: AbstractDataPoint
    datetime
    isdst
    duration
end

struct VoltageEventsCount <: AbstractDataPoint
    obis
    kind
    phase
    count
end

struct TextMessage <: AbstractDataPoint
    obis
    channel
    text
end

struct InstantaneousReading <: AbstractDataPoint
    obis
    kind
    direction
    phase
    value
    unit
end

struct ActiveThresholdData <: AbstractDataPoint
    obis
    value
    unit
end

struct BreakerStateData <: AbstractDataPoint
    obis
    value
end

struct EquipmentIdentifier <: AbstractDataPoint
    obis
    channel
    id
end

struct MBusDeviceType <: AbstractDataPoint
    obis
    channel
    kind
end

struct MBusMeterReading <: AbstractDataPoint
    obis
    channel
    datetime
    isdst
    value
    unit
end

struct MBusGasValvePosition <: AbstractDataPoint
    obis
    position
end

const mbus_device_type = Dict(
    0x00 => :other,
    0x01 => :oil,
    0x02 => :electricity,
    0x03 => :gas,
    0x04 => :heat,
    0x05 => :steam,
    0x06 => :warm_water,
    0x07 => :water,
    0x08 => :heat_cost_allocator,
    0x09 => :compessed_air,
    0x0a => :cooling_load_meter_outlet,
    0x0b => :cooling_load_meter_inlet,
    0x0c => :heat_inlet,
    0x0d => :heat_cooling_load_meter,
    0x0e => :bus_system_component,
    0x0f => :unknown_medium,
    0x15 => :hot_water,
    0x16 => :cold_water,
    0x17 => :dual_register_water_meter,
    0x18 => :pressure,
    0x19 => :ad_converter,
)

abstract type DLMSPacket end
abstract type SmartyPacket <: DLMSPacket end

struct EncryptedPacket <: SmartyPacket
    system_title_bytes::Vector{UInt8}
    frame_counter_bytes::Vector{UInt8}
    ciphertext
    gcm_tag::Vector{UInt8}
end

struct DecryptedPacket <: SmartyPacket
    plaintext
    frame_counter::Integer
end

struct ParsedPacket <: SmartyPacket
    frame_counter::Integer
    datetime::Dates.AbstractDateTime
    data::Vector{AbstractDataPoint}
end

function Base.read(io::IO, ::Type{EncryptedPacket})
    # start byte
    if read(io, UInt8) !== 0xdb
        error("Could not parse EncryptedPacket. Unexpected start byte")
    end

    # system title
    system_title_length = read(io, UInt8) |> Int64
    if system_title_length != 8
        error("Could not parse EncryptedPacket. Unexpected system title length ($(system_title_length) ≠ 8)")
    end
    system_title_bytes = read(io, system_title_length)
    # Is this static over all packets and/or devices?
    # @assert system_title_bytes == [0x53, 0x41, 0x47, 0x67, 0x70, 0x01, 0xb4, 0xc7]

    # verify separator byte
    if read(io, UInt8) !== 0x82
        error("Could not parse EncryptedPacket. Unexpected value for first separator byte")
    end

    remaining_length = ntoh( read(io, UInt16) ) |> Int64
    if !((12 + 4 + 1) < remaining_length < 2048)
        error("Could not parse EncryptedPacket. Unexpected data length $(remaining_length)")
    end

    # verify separator byte
    if read(io, UInt8) !== 0x30
        error("Could not parse EncryptedPacket. Unexpected value for second separator byte")
    end

    frame_counter_bytes = read(io, 4)

    ciphertext = read(io, remaining_length - 1 - 4 - 12)

    gcm_tag = read(io, 12)

    EncryptedPacket(system_title_bytes, frame_counter_bytes, ciphertext, gcm_tag)
end

function Base.write(io::IO, encrypted_packet::EncryptedPacket)
    @unpack system_title_bytes, frame_counter_bytes, ciphertext, gcm_tag = encrypted_packet

    write(io, 0xdb)
    write(io, 0x08)
    write(io, system_title_bytes)
    write(io, 0x82)
    write(io, hton(Int16(length(ciphertext) + 12 + 4 + 1)))
    write(io, 0x30)
    write(io, frame_counter_bytes)
    write(io, ciphertext)
    write(io, gcm_tag)
end

const aad = hex2bytes("3000112233445566778899aabbccddeeff")

function decrypt_smarty_packet(key::AbstractVector{UInt8}, encrypted_packet::EncryptedPacket)
    @unpack system_title_bytes, frame_counter_bytes, ciphertext, gcm_tag = encrypted_packet

    iv = vcat(system_title_bytes, frame_counter_bytes)

    data = aes128_gcm_decrypt(key, iv, aad, gcm_tag, ciphertext)

    frame_counter = ntoh( first(reinterpret(Int32, frame_counter_bytes)) ) |> Int64

    DecryptedPacket(data, frame_counter)
end

encrypt_smarty_packet(key::AbstractVector{UInt8}, plaintext::AbstractVector{UInt8}; frame_counter = 1, system_title_bytes = [0x53, 0x41, 0x47, 0x67, 0x70, 0x01, 0xb4, 0xc7]) = encrypt_smarty_packet(key, DecryptedPacket(plaintext, frame_counter), system_title_bytes = system_title_bytes)

function encrypt_smarty_packet(key::AbstractVector{UInt8}, decrypted_packet::DecryptedPacket; system_title_bytes = [0x53, 0x41, 0x47, 0x67, 0x70, 0x01, 0xb4, 0xc7])
    @unpack plaintext, frame_counter = decrypted_packet
    frame_counter_bytes = hton_bytes(UInt32, frame_counter)

    iv = vcat(system_title_bytes, frame_counter_bytes)

    ciphertext, gcm_tag = aes128_gcm_encrypt(key, iv, aad, plaintext)

    EncryptedPacket(system_title_bytes, frame_counter_bytes, ciphertext, gcm_tag)
end

function parse_timestamp(str)
    dt = DateTime(str[1:end-1], "yymmddHHMMSS")
    if dt < Date(2000)
        dt += Year(2000)
    end
    dt, str[end] === 'S' ? true : str[end] === 'W' ? false : missing
end

function parse_telegram(plaintext::Union{AbstractString, AbstractVector{UInt8}}; check_crc = :error)
    dp = DecryptedPacket(plaintext, nothing)
    parse_telegram(dp)
end

function parse_telegram(decrypted_packet::DecryptedPacket; check_crc = :error)
    plaintext = String(decrypted_packet.plaintext)

    m = match(r"""
        \/(?<flag_id>\w{3})5(?<meter_type>.+)\r\n
        \r\n
        (?<data>.*\r\n)*
        \!(?<crc>\w{4})\r\n
    """isx, plaintext)

    # check crc
    crc_c = crc16_ibm_lsb(codeunits(m.match[1:end-6]))
    crc_e = ntoh( first(reinterpret(UInt16, hex2bytes(m[:crc]) )) )
    if crc_e !== crc_c
        if check_crc === :error
            error("CRC check failed")
        elseif check_crc === :warn
            @warn "CRC check failed"
        end
    end

    data = AbstractDataPoint[]

    push!(data, ManufacturerFlagIdentifier(m[:flag_id]))
    push!(data, ManufacturerTypeIdentifier(m[:meter_type]))

    for line_match in eachmatch(r"^(?<obis>\d-\d+:\d+\.\d+\.\d+)(?<data>.*)\r\n"m, m[:data])
        obis = line_match[:obis]
        values = [value_match[1] for value_match in eachmatch(r"\(([^()]*)\)", line_match[:data])]

        # 0-0:1.0.0 - timestamp of P1 message
        if obis == "0-0:1.0.0"
            dt, isdst = parse_timestamp(values[1])
            push!(data, Timestamp(obis, dt, isdst))

        # 0-0:17.0.0 - active threshold (SMAX)
        elseif obis == "0-0:17.0.0"
            vm = match(r"(?<value>\d+(\.\d+)?)(?:\*(?<unit>.+))?", values[1])
            value = parse(Float64, vm[:value])
            unit = vm[:unit] === nothing ? missing : vm[:unit]
            push!(data, ActiveThresholdData(obis, value, unit))

        # 0-0:42.0.0 - equipment logical name
        elseif obis == "0-0:42.0.0"
            push!(data, EquipmentName(obis, String(hex2bytes(values[1]))) )

        # 0-0:96.1.1 - equipment identifier
        elseif obis == "0-0:96.1.1"
            push!(data, EquipmentIdentifier(obis, 0, hex2bytes(values[1])))

        # 0-0:96.3.10 - breaker control state
        elseif obis == "0-0:96.3.10"
            push!(data, BreakerStateData(obis, parse(Int64, values[1])))

        # 0-0:96.7.9 - number of long power failures
        elseif obis == "0-0:96.7.9"
            push!(data, PowerFailureCount(obis, :long, parse(Int64, values[1])))

        # 0-0:96.7.21 - number of power failures
        elseif obis == "0-0:96.7.21"
            push!(data, PowerFailureCount(obis, :total, parse(Int64, values[1])))

        # 0-0:96.13.n - text message
        elseif (mi = match(r"0-0:96.13.(?<channel>\d+)", obis)) != nothing
            channel = parse(Int64, mi[:channel])
            push!(data, TextMessage(obis, channel, String(hex2bytes(values[1])) ))

        # 0-0:96.14.0 - tariff indicator
        elseif obis == "0-0:96.14.0"
            push!(data, TariffIndicator(obis, parse(Int64, values[1])))

        # 1-3:0.2.8 - version of P1 message
        elseif obis == "1-3:0.2.8"
            push!(data, Version(obis, values[1]))

        # 1-0:d.7.t - meter reading: electricity power delivered by/to client in tariff
        elseif (mi = match(r"1-0:(?<direction>[1234]).7.(?<tariff>\d)", obis)) != nothing
            kind = mi[:direction] ∈ ["1", "2"] ? :active : mi[:direction] ∈ ["3", "4"] ? :reactive : error()
            direction = mi[:direction] ∈ ["1", "3"] ? :in : mi[:direction] ∈ ["2", "4"] ? :out : error()
            tariff = parse(Int64, mi[:tariff])

            vm = match(r"(?<value>\d+\.\d+)(?:\*(?<unit>.+))?", values[1])
            value = parse(Float64, vm[:value])
            unit = vm[:unit] === nothing ? missing : vm[:unit]

            push!(data, ElectricityPowerMeterReading(obis, kind, direction, tariff, value, unit))

        # 1-0:d.8.t - meter reading: electricity energy delivered by/to client in tariff
        elseif (mi = match(r"1-0:(?<direction>[1234]).8.(?<tariff>\d)", obis)) != nothing
            kind = mi[:direction] ∈ ["1", "2"] ? :active : mi[:direction] ∈ ["3", "4"] ? :reactive : error()
            direction = mi[:direction] ∈ ["1", "3"] ? :in : mi[:direction] ∈ ["2", "4"] ? :out : error()
            tariff = parse(Int64, mi[:tariff])

            vm = match(r"(?<value>\d+\.\d+)(?:\*(?<unit>.+))?", values[1])
            value = parse(Float64, vm[:value])
            unit = vm[:unit] === nothing ? missing : vm[:unit]

            push!(data, ElectricityEnergyMeterReading(obis, kind, direction, tariff, value, unit))

        # 1-0:pk.7.0 - Instantaneous voltage/current/power
        elseif (mi = match(r"1-0:(?<phase>[234567])(?<kind>[1234]).7.0", obis)) != nothing
            phase = mi[:phase] ∈ ["2", "3"] ? :L1 : mi[:phase] ∈ ["4", "5"] ? :L2 : mi[:phase] ∈ ["6", "7"] ? :L3 : error()

            if mi[:phase] ∈ ["3", "5", "7"]
                kind = mi[:kind] == "2" ? :voltage : mi[:kind] == "1" ? :current : error("Unexpected kind")
                direction = :na
            else
                kind = mi[:kind] ∈ ["1", "2"] ? :power_active : mi[:kind] ∈ ["3", "4"] ? :power_reactive : error()
                direction = mi[:kind] ∈ ["1", "3"] ? :in : mi[:kind] ∈ ["2", "4"] ? :out : error()
            end

            vm = match(r"(?<value>\d+(\.\d+)?)\*(?<unit>.+)", values[1])
            value = parse(Float64, vm[:value])
            unit = vm[:unit] === nothing ? missing : vm[:unit]

            push!(data, InstantaneousReading(obis, kind, direction, phase, value, unit))

        # 1-0:p2.3k.0 - number of voltage sags/swells
        elseif (mi = match(r"1-0:(?<phase>[357]2).(?<kind>3[26]).0", obis)) != nothing
            phase = mi[:phase] == "32" ? :L1 : mi[:phase] == "52" ? :L2 : mi[:phase] == "72" ? :L3 : error()
            kind = mi[:kind] == "32" ? :sag : mi[:kind] == "36" ? :swell : error()

            push!(data, VoltageEventsCount(obis, kind, phase, parse(Int64, values[1])))

        # 1-0:99.97.0 - power failure event log
        elseif obis == "1-0:99.97.0"

            events = PowerFailure[]
            for i in 3:2:(1 + 2 * parse(Int64, values[1]))
                dt, isdst = parse_timestamp(values[i])
                vm = match(r"(?<value>\d+)\*(?<unit>.+)", values[i+1])
                duration = Dates.Second(parse(Int64, vm[:value]))
                if vm[:unit] != "s"
                    error("unexpected unit for power failure duration")
                end
                push!(events, PowerFailure(dt, isdst, duration))
            end

            push!(data, PowerFailureLog(obis, events))

        # M-Bus

        # 0-n:24.1.0 - M-Bus client device type
        elseif (mi = match(r"0-(?<channel>\d+):24.1.0", obis)) != nothing
            channel = parse(Int64, mi[:channel])
            kind = parse(Int64, values[1])
            push!(data, MBusDeviceType(obis, channel, mbus_device_type[kind]))

        # 0-n:96.1.0 - M-Bus client equipment identifier
        elseif (mi = match(r"0-(?<channel>\d+):96.1.0", obis)) != nothing
            channel = parse(Int64, mi[:channel])
            push!(data, EquipmentIdentifier(obis, channel, hex2bytes(values[1])))

        # 0-n:24.2.1 - M-Bus client meter reading
        elseif (mi = match(r"0-(?<channel>\d+):24.2.1", obis)) != nothing
            channel = parse(Int64, mi[:channel])
            dt, isdst = parse_timestamp(values[1])

            vm = match(r"(?<value>\d+(\.\d+)?)\*(?<unit>.+)", values[2])
            value = parse(Float64, vm[:value])
            unit = vm[:unit] === nothing ? missing : vm[:unit]

            push!(data, MBusMeterReading(obis, channel, dt, isdst, value, unit))

        # 0-n:24.4.0 - M-Bus client gas valve position
        elseif (mi = match(r"0-(?<channel>\d+):24.4.0", obis)) != nothing
            channel = parse(Int64, mi[:channel])
            push!(data, MBusGasValvePosition(obis, channel, parse(Int64, values[1])))

        else
            push!(data, UnknownData(obis, values))
        end

    end

    tsp = data[findfirst(p -> isa(p, Smarty.Timestamp), data)]
    zdt = ZonedDateTime(tsp.datetime, tz"Europe/Luxembourg", tsp.isdst)

    ParsedPacket(decrypted_packet.frame_counter, zdt, data)
end

end # module
