"""
    encrypt(data::Vector{<:Real}, public_key::PublicKey, context::SecureContext)

Encrypt `data` into a [`SecureVector`](@ref) using the `public_key` derived for the given
`context`.

See also: [`SecureVector`](@ref), [`decrypt`](@ref)
"""
function encrypt(data::Vector{<:Real}, public_key::PublicKey, context::SecureContext)
    encrypt_impl(data, public_key, context)
end

"""
    encrypt(plain_vector::PlainVector, public_key::PublicKey)

Encrypt `plain_vector` into a [`SecureVector`](@ref) using the `public_key`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`decrypt`](@ref)
"""
function encrypt(plain_vector::PlainVector, public_key::PublicKey)
    encrypt_impl(plain_vector, public_key)
end

"""
    decrypt!(plain_vector::PlainVector, secure_vector::SecureVector, private_key::PrivateKey)

Decrypt `secure_vector` using the `private_key` and store the result in the given
`plain_text`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`decrypt`](@ref)
"""
function decrypt!(plain_vector::PlainVector, secure_vector::SecureVector,
                  private_key::PrivateKey)
    decrypt_impl!(plain_vector, secure_vector, private_key)
end


"""
    decrypt(secure_vector::SecureVector, private_key::PrivateKey)

Decrypt `secure_vector` using the `private_key` and return the resulting `PlainVector`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`decrypt!`](@ref)
"""
function decrypt(secure_vector::SecureVector, private_key::PrivateKey)
    decrypt_impl(secure_vector, private_key)
end

function encrypt(plain_matrix::PlainMatrix, public_key::PublicKey)
    encrypt_impl(plain_matrix, public_key)
end

function decrypt!(plain_matrix::PlainMatrix, secure_matrix::SecureMatrix,
    private_key::PrivateKey)
    decrypt_impl!(plain_matrix, secure_matrix, private_key)
end

function decrypt(secure_matrix::SecureMatrix, private_key::PrivateKey)
    decrypt_impl(secure_matrix, private_key)
end