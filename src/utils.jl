
function hton_bytes(v::Integer)
    io = IOBuffer(sizehint = sizeof(v))
    write(io, hton(v))
    take!(io)
end

function hton_bytes(T::Type{<: Integer}, v::Integer)
    io = IOBuffer(sizehint = sizeof(T))
    write(io, hton(T(v)))
    take!(io)
end

function crc16_ibm_lsb(bytearray)
    len = length(bytearray)
    rem = 0x0000

    for i in 1:len
        rem = rem ⊻ bytearray[i]
        for j in 1:8
            if rem & 0x0001 == 0x0001
                rem = (rem >> 1) ⊻ 0xA001
            else
                rem = (rem >> 1)
            end
        end
    end
    rem
end
