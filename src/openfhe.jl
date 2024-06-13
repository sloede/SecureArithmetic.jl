"""
    OpenFHEBackend

Cryptography backend for use with the homomorphic encryption library OpenFHE
(https://github.com/openfheorg/openfhe-development).

See also: [`SecureContext`](@ref), [`Unencrypted`](@ref)
"""
struct OpenFHEBackend{CryptoContextT} <: AbstractCryptoBackend
    crypto_context::CryptoContextT
end

"""
    get_crypto_context(context::SecureContext{<:OpenFHEBackend})

Return a `OpenFHE.CryptoContext` object stored in a given `context`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref)
"""
function get_crypto_context(context::SecureContext{<:OpenFHEBackend})
    context.backend.crypto_context
end
"""
    get_crypto_context(v::Union{SecureVector{<:OpenFHEBackend},
                                PlainVector{<:OpenFHEBackend}})

Return a `OpenFHE.CryptoContext` object stored in `v`.

See also: [`SecureContext`](@ref), [`SecureVector`](@ref), [`PlainVector`](@ref),
[`OpenFHEBackend`](@ref)
"""
function get_crypto_context(v::Union{SecureVector{<:OpenFHEBackend},
                                     PlainVector{<:OpenFHEBackend}})
    get_crypto_context(v.context)
end

"""
    generate_keys(context::SecureContext{<:OpenFHEBackend})

Generate and return public and private keys.

See also: [`PublicKey`](@ref), [`PrivateKey`](@ref), [`SecureContext`](@ref),
[`OpenFHEBackend`](@ref)
"""
function generate_keys(context::SecureContext{<:OpenFHEBackend})
    cc = get_crypto_context(context)
    keys = OpenFHE.KeyGen(cc)
    public_key = PublicKey(context, OpenFHE.public_key(keys))
    private_key = PrivateKey(context, OpenFHE.private_key(keys))

    public_key, private_key
end

"""
    init_multiplication!(context::SecureContext{<:OpenFHEBackend},
                         private_key::PrivateKey)

Generate relinearization key for use with `OpenFHE.EvalMult` using the `private_key`, and
store it in the given `context`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref)
"""
function init_multiplication!(context::SecureContext{<:OpenFHEBackend},
                              private_key::PrivateKey)
    cc = get_crypto_context(context)
    OpenFHE.EvalMultKeyGen(cc, private_key.private_key)

    nothing
end

"""
    init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                   shifts)

Generate rotation keys for use with `OpenFHE.EvalRotate` using the `private_key` and for the
rotation indexes in `shifts`. The keys are stored in the given `context`.
Positive shift defines rotation to the right, e.g. a rotation with a shift 1:
[1, 2, 3, 4] -> [4, 1, 2, 3].
Negative shift defines rotation to the left, e.g. a rotation with a shift -1:
[1, 2, 3, 4] -> [2, 3, 4, 1].

Note: Here, indexes stored in `shifts` have reversed sign compared to rotation indexes used in
OpenFHE.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref)
"""
function init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                        shifts)
    cc = get_crypto_context(context)
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, -shifts)

    nothing
end

"""
    init_bootstrapping!(context::SecureContext{<:OpenFHEBackend},
                        private_key::PrivateKey)

Generate the necessary keys from `private_key` to enable bootstrapping for a given
`context`. Supported for CKKS only.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref),
[`bootstrap!`](@ref)
"""
function init_bootstrapping!(context::SecureContext{<:OpenFHEBackend},
                             private_key::PrivateKey)
    cc = get_crypto_context(context)
    encoding_parameters = OpenFHE.GetEncodingParams(cc)
    slots = OpenFHE.GetBatchSize(encoding_parameters)
    OpenFHE.EvalBootstrapKeyGen(cc, private_key.private_key, slots)

    nothing
end

"""
    PlainVector(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend})

Constructor for data type [`PlainVector`](@ref) takes an unencrypted `data` vector and a `context`
object of type `SecureContext{<:OpenFHEBackend}`. Return [`PlainVector`](@ref) with encoded but
not encrypted data. The `context` can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureVector`](@ref).

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
[`OpenFHEBackend`](@ref)
"""
function PlainVector(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend})
    cc = get_crypto_context(context)
    plaintext = OpenFHE.MakeCKKSPackedPlaintext(cc, data)
    capacity = OpenFHE.GetSlots(plaintext)
    plain_vector = PlainVector(plaintext, length(data), capacity, context)

    plain_vector
end

"""
    PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})

Constructor for data type [`PlainVector`](@ref) takes an unencrypted `data` vector and a `context`
object of type `SecureContext{<:OpenFHEBackend}`. Return [`PlainVector`](@ref) with encoded but
not encrypted data. The `context` can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureVector`](@ref).
    
See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
[`OpenFHEBackend`](@ref)
"""
function PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})
    PlainVector(convert(Vector{Float64}, data), context)
end

function Base.show(io::IO, v::PlainVector{<:OpenFHEBackend})
    print(io, collect(v))
end

function Base.show(io::IO, ::MIME"text/plain", v::PlainVector{<:OpenFHEBackend})
    print(io, v.length, "-element PlainVector{OpenFHEBackend}:\n")
    Base.print_matrix(io, collect(v))
end

"""
    collect(v::PlainVector{<:OpenFHEBackend})

Decode and return the real-valued data contained in `v`.

See also: [`PlainVector`](@ref), [`OpenFHEBackend`](@ref)
"""
function Base.collect(v::PlainVector{<:OpenFHEBackend})
    collect(OpenFHE.GetRealPackedValue(v.data)[1:v.length])
end

"""
    level(v::Union{SecureVector{<:OpenFHEBackend}, PlainVector{<:OpenFHEBackend}})

Return the number of scalings, referred to as the level, performed over `v`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`OpenFHEBackend`](@ref)
"""
function level(v::Union{SecureVector{<:OpenFHEBackend}, PlainVector{<:OpenFHEBackend}})
    Int(OpenFHE.GetLevel(v.data))
end

function encrypt_impl(data::Vector{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:OpenFHEBackend})
    plain_vector = PlainVector(data, context)
    secure_vector = encrypt(plain_vector, public_key)

    secure_vector
end

function encrypt_impl(plain_vector::PlainVector{<:OpenFHEBackend}, public_key::PublicKey)
    context = plain_vector.context
    cc = get_crypto_context(context)
    ciphertext = OpenFHE.Encrypt(cc, public_key.public_key, plain_vector.data)
    capacity = OpenFHE.GetSlots(ciphertext)
    secure_vector = SecureVector(ciphertext, length(plain_vector), capacity, context)

    secure_vector
end

function decrypt_impl!(plain_vector::PlainVector{<:OpenFHEBackend},
                       secure_vector::SecureVector{<:OpenFHEBackend},
                       private_key::PrivateKey)
    cc = get_crypto_context(secure_vector)
    OpenFHE.Decrypt(cc, private_key.private_key, secure_vector.data,
                    plain_vector.data)

    plain_vector
end

function decrypt_impl(secure_vector::SecureVector{<:OpenFHEBackend},
                      private_key::PrivateKey)
    context = secure_vector.context
    plain_vector = PlainVector(OpenFHE.Plaintext(), length(secure_vector),
                               capacity(secure_vector), context)

    decrypt!(plain_vector, secure_vector, private_key)
end

"""
    bootstrap!(secure_vector::SecureVector{<:OpenFHEBackend})
     
Refresh a given `secure_vector` to increase the multiplication depth. Supported for CKKS only.

See also: [`SecureVector`](@ref), [`OpenFHEBackend`](@ref), [`init_bootstrapping!`](@ref)
"""
function bootstrap!(secure_vector::SecureVector{<:OpenFHEBackend})
    context = secure_vector.context
    cc = get_crypto_context(context)
    secure_vector.data = OpenFHE.EvalBootstrap(cc, secure_vector.data)

    secure_vector
end


############################################################################################
# Arithmetic operations
############################################################################################

function add(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalAdd(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), capacity(sv1), sv1.context)

    secure_vector
end

function add(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalAdd(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function add(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalAdd(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalSub(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), capacity(sv1), sv1.context)

    secure_vector
end

function subtract(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(pv::PlainVector{<:OpenFHEBackend}, sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, pv.data, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(scalar::Real, sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, scalar, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function negate(sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalNegate(cc, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function multiply(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalMult(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), capacity(sv1), sv1.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function rotate(sv::SecureVector{<:OpenFHEBackend}, shift; wrap_by)
    cc = get_crypto_context(sv)

    # We use `-shift` to match Julia's usual `circshift` direction
    ciphertext_rotated = OpenFHE.EvalRotate(cc, sv.data, -shift)

    if wrap_by == :length && length(sv) < capacity(sv)
        # Mask rotated ciphertext
        mask_rotated = zeros(capacity(sv))
        if shift < 0
            first = 1
            last = length(sv) - abs(shift)
            mask_rotated[first:last] .= 1
        else
            first = abs(shift) + 1
            last = length(sv)
            mask_rotated[first:last] .= 1
        end
        plaintext1 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask_rotated)
        ciphertext1 = OpenFHE.EvalMult(cc, ciphertext_rotated, plaintext1)

        # Compute remaining part of the ciphertext
        shift_rest = -sign(shift) * (length(sv) - abs(shift))
        ciphertext_rest = OpenFHE.EvalRotate(cc, sv.data, -shift_rest)

        # Mask remaining part of the ciphertext
        mask_rest = zeros(capacity(sv))
        if shift < 0
            first = length(sv) - abs(shift) + 1
            last = length(sv)
            mask_rest[first:last] .= 1
        else
            first = 1
            last = abs(shift)
            mask_rest[first:last] .= 1
        end
        plaintext2 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask_rest)
        ciphertext2 = OpenFHE.EvalMult(cc, ciphertext_rest, plaintext2)

        ciphertext_final = OpenFHE.EvalAdd(cc, ciphertext1, ciphertext2)
        secure_vector = SecureVector(ciphertext_final, length(sv), capacity(sv),
                                     sv.context)
    else
        # If wrapping by capacity is requested and length is less than capacity
        secure_vector = SecureVector(ciphertext_rotated, length(sv), capacity(sv),
                                     sv.context)
    end

    secure_vector
end

############################################################################################
# Matrix
############################################################################################

function PlainMatrix(data::Vector{Vector{Float64}}, context::SecureContext)
    plain_vectors = PlainVector.(data, Ref(context))
    plain_matrix = PlainMatrix(plain_vectors, length(data), context)

    plain_matrix
end
function PlainMatrix(data::Vector{DataT}, context::SecureContext) where DataT<:Vector{<:Real}
    PlainMatrix(convert(Vector{Vector{Float64}}, data), context)
end
function PlainMatrix(data::Matrix{<:Real}, context::SecureContext)
    PlainMatrix(Vector{Float64}[eachrow(data)...], context)
end

function Base.show(io::IO, m::PlainMatrix{<:OpenFHEBackend})
    print(io, collect(m))
end

function Base.show(io::IO, ::MIME"text/plain", m::PlainMatrix{<:OpenFHEBackend})
    print(io, m.length*m.data[1].length, "-element PlainMatrix{OpenFHEBackend}:\n")
    Base.print_matrix(io, collect(m))
end

function Base.collect(m::PlainMatrix)
    collect.(m.data)
end

function level(m::Union{SecureMatrix, PlainMatrix})
    level(m.data[1])
end

function encrypt_impl(plain_matrix::PlainMatrix, public_key::PublicKey)
    secure_vectors = encrypt.(plain_matrix.data, Ref(public_key))
    secure_matrix = SecureMatrix(secure_vectors, length(plain_matrix), plain_matrix.context)

    secure_matrix
end

function decrypt_impl!(plain_matrix::PlainMatrix{<:OpenFHEBackend},
                       secure_matrix::SecureMatrix{<:OpenFHEBackend}, private_key::PrivateKey)
    decrypt_impl!.(plain_matrix.data, secure_matrix.data, Ref(private_key))

    plain_matrix
end

function decrypt_impl(secure_matrix::SecureMatrix{<:OpenFHEBackend}, private_key::PrivateKey)
    context = secure_matrix.context
    plain_matrix = PlainMatrix([PlainVector(OpenFHE.Plaintext(), length(sv), capacity(sv), context)
                                for sv in secure_matrix.data],
                               length(secure_matrix), context)

    decrypt!(plain_matrix, secure_matrix, private_key)
end

function bootstrap!(secure_matrix::SecureMatrix)
    bootstrap!.(secure_matrix.data)

    secure_matrix
end


############################################################################################
# Arithmetic operations on matrix
############################################################################################
# All operations are defined elementwise 
function add(sm1::SecureMatrix, sm2::SecureMatrix)
    secure_matrix = SecureMatrix(add.(sm1.data, sm2.data), length(sm1), sm1.context)

    secure_matrix
end

function add(sm::SecureMatrix, pm::PlainMatrix)
    secure_matrix = SecureMatrix(add.(sm.data, pm.data), length(sm), sm.context)

    secure_matrix
end

function add(sm::SecureMatrix, scalar::Real)
    secure_matrix = SecureMatrix(add.(sm.data, scalar), length(sm), sm.context)

    secure_matrix
end

function add(sm::SecureMatrix, sv::SecureVector)
    secure_matrix = SecureMatrix(add.(sm.data, Ref(sv)), length(sm), sm.context)

    secure_matrix
end

function add(sm::SecureMatrix, pv::PlainVector)
    secure_matrix = SecureMatrix(add.(sm.data, Ref(pv)), length(sm), sm.context)

    secure_matrix
end

function subtract(sm1::SecureMatrix, sm2::SecureMatrix)
    secure_matrix = SecureMatrix(subtract.(sm1.data, sm2.data), length(sm1), sm1.context)

    secure_matrix
end

function subtract(sm::SecureMatrix, pm::PlainMatrix)
    secure_matrix = SecureMatrix(subtract.(sm.data, pm.data), length(sm), sm.context)

    secure_matrix
end

function subtract(pm::PlainMatrix, sm::SecureMatrix)
    secure_matrix = SecureMatrix(subtract.(pm.data, sm.data), length(sm), sm.context)

    secure_matrix
end

function subtract(sm::SecureMatrix, scalar::Real)
    secure_matrix = SecureMatrix(subtract.(sm.data, scalar), length(sm), sm.context)

    secure_matrix
end

function subtract(scalar::Real, sm::SecureMatrix)
    secure_matrix = SecureMatrix(subtract.(scalar, sm.data), length(sm), sm.context)

    secure_matrix
end

function subtract(sm::SecureMatrix, sv::SecureVector)
    secure_matrix = SecureMatrix(subtract.(sm.data, Ref(sv)), length(sm), sm.context)

    secure_matrix
end

function subtract(sv::SecureVector, sm::SecureMatrix)
    secure_matrix = SecureMatrix(subtract.(Ref(sv), sm.data), length(sm), sm.context)

    secure_matrix
end

function subtract(sm::SecureMatrix, pv::PlainVector)
    secure_matrix = SecureMatrix(subtract.(sm.data, Ref(pv)), length(sm), sm.context)

    secure_matrix
end

function subtract(pv::PlainVector, sm::SecureMatrix)
    secure_matrix = SecureMatrix(subtract.(Ref(pv), sm.data), length(sm), sm.context)

    secure_matrix
end

function negate(sm::SecureMatrix)
    secure_matrix = SecureMatrix(negate.(sm.data), length(sm), sm.context)

    secure_matrix
end

function multiply(sm1::SecureMatrix, sm2::SecureMatrix)
    secure_matrix = SecureMatrix(multiply.(sm1.data, sm2.data), length(sm1), sm1.context)

    secure_matrix
end

function multiply(sm::SecureMatrix, pm::PlainMatrix)
    secure_matrix = SecureMatrix(multiply.(sm.data, pm.data), length(sm), sm.context)

    secure_matrix
end

function multiply(sm::SecureMatrix, scalar::Real)
    secure_matrix = SecureMatrix(multiply.(sm.data, scalar), length(sm), sm.context)

    secure_matrix
end

function multiply(sm::SecureMatrix, sv::SecureVector)
    secure_matrix = SecureMatrix(multiply.(sm.data, Ref(sv)), length(sm), sm.context)

    secure_matrix
end

function multiply(sm::SecureMatrix, pv::PlainVector)
    secure_matrix = SecureMatrix(multiply.(sm.data, Ref(pv)), length(sm), sm.context)

    secure_matrix
end

function rotate(sm::SecureMatrix, shift; wrap_by)
    # rotation along x axis
    secure_matrix_rotated = deepcopy(sm)
    if shift[1]!= 0
        secure_matrix_rotated = SecureMatrix(rotate.(sm.data, shift[1]; wrap_by), length(sm), sm.context)
    end
    # rotation along y axis
    circshift!(secure_matrix_rotated.data, shift[2])

    secure_matrix_rotated
end