
import MbedTLS

function aes128_gcm_decrypt(key, iv, aad, tag, ciphertext)
    cipher = MbedTLS.Cipher(MbedTLS.CIPHER_AES_128_GCM)
    MbedTLS.set_key!(cipher, key, MbedTLS.DECRYPT)

    plaintext = Vector{UInt8}(undef, cld(sizeof(ciphertext), 16) * 16)
    fill!(plaintext, 0x00)
    plaintext_length_ref = Ref{Csize_t}(sizeof(plaintext))

    MbedTLS.@err_check ccall((:mbedtls_cipher_auth_decrypt, MbedTLS.libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Ptr{Csize_t}, Ptr{Cvoid}, Csize_t),
        cipher.data,
        iv, sizeof(iv),
        aad, sizeof(aad),
        ciphertext, sizeof(ciphertext),
        plaintext, plaintext_length_ref,
        tag, sizeof(tag))

    plaintext_length = Int(plaintext_length_ref[])
    resize!(plaintext, plaintext_length)

    plaintext
end

function aes128_gcm_encrypt(key, iv, aad, plaintext; tag_length = 12)
    cipher = MbedTLS.Cipher(MbedTLS.CIPHER_AES_128_GCM)
    MbedTLS.set_key!(cipher, key, MbedTLS.ENCRYPT)

    ciphertext = Vector{UInt8}(undef, cld(sizeof(plaintext), 16) * 16)
    fill!(ciphertext, 0x00)
    ciphertext_length_ref = Ref{Csize_t}(sizeof(ciphertext))

    tag = Vector{UInt8}(undef, tag_length)
    fill!(tag, 0x00)

    MbedTLS.@err_check ccall((:mbedtls_cipher_auth_encrypt, MbedTLS.libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Ptr{Csize_t}, Ptr{Cvoid}, Csize_t),
        cipher.data,
        iv, sizeof(iv),
        aad, sizeof(aad),
        plaintext, sizeof(plaintext),
        ciphertext, ciphertext_length_ref,
        tag, sizeof(tag))

    ciphertext_length = Int(ciphertext_length_ref[])
    resize!(ciphertext, ciphertext_length)

    ciphertext, tag
end
