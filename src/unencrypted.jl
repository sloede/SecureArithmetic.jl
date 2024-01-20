struct Unencrypted <: AbstractCryptoBackend
    # No data fields required
end

function generate_keys(context::SecureContext{<:Unencrypted})
    PublicKey(context, nothing), PrivateKey(context, nothing)
end

init_multiplication!(context::SecureContext{<:Unencrypted}, private_key) = nothing
init_rotation!(context::SecureContext{<:Unencrypted}, private_key, shifts) = nothing
init_bootstrapping!(context::SecureContext{<:Unencrypted}, private_key) = nothing

# No constructor for `PlainVector` necessary since we can directly use the inner constructor

function encrypt(data::Vector{<:Real}, public_key, context::SecureContext{<:Unencrypted})
    SecureVector(data, context)
end

function encrypt(plain_vector::PlainVector{<:Unencrypted}, public_key)
    SecureVector(plain_vector.plaintext, plain_vector.context)
end

function decrypt!(plain_vector::PlainVector{<:Unencrypted},
                  secure_vector::SecureVector{<:Unencrypted}, private_key)
    plain_vector.plaintext .= secure_vector.ciphertext

    plain_vector
end

function decrypt(secure_vector::SecureVector{<:Unencrypted}, private_key)
    plain_vector = PlainVector(similar(secure_vector.ciphertext), secure_vector.context)

    decrypt!(plain_vector, secure_vector, private_key)
end

bootstrap!(secure_vector::SecureVector{<:Unencrypted}) = secure_vector

function add(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.ciphertext .+ sv2.ciphertext, sv1.context)
end

function add(sv::SecureVector{<:Unencrypted}, pv::PlainVector{<:Unencrypted})
    SecureVector(sv.ciphertext .+ pv.plaintext, sv.context)
end

function subtract(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.ciphertext .- sv2.ciphertext, sv1.context)
end

function subtract(sv::SecureVector{<:Unencrypted}, pv::PlainVector{<:Unencrypted})
    SecureVector(sv.ciphertext .- pv.plaintext, sv.context)
end

function subtract(pv::PlainVector{<:Unencrypted}, sv::SecureVector{<:Unencrypted})
    SecureVector(pv.plaintext .- sv.ciphertext, sv.context)
end

function negate(sv::SecureVector{<:Unencrypted})
    SecureVector(-sv.ciphertext, sv.context)
end

function multiply(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.ciphertext .* sv2.ciphertext, sv1.context)
end

function multiply(sv::SecureVector{<:Unencrypted}, pv::PlainVector{<:Unencrypted})
    SecureVector(sv.ciphertext .* pv.plaintext, sv.context)
end

function multiply(sv::SecureVector{<:Unencrypted}, scalar::Real)
    SecureVector(sv.ciphertext .* scalar, sv.context)
end

function rotate(sv::SecureVector{<:Unencrypted}, shift)
    SecureVector(circshift(sv.ciphertext, shift), sv.context)
end