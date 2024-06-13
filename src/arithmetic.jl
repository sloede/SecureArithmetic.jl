# Add
Base.:+(sv1::SecureVector, sv2::SecureVector) = add(sv1, sv2)
Base.:+(sv::SecureVector, pv::PlainVector) = add(sv, pv)
Base.:+(pv::PlainVector, sv::SecureVector) = add(sv, pv)
Base.:+(sv::SecureVector, scalar::Real) = add(sv, scalar)
Base.:+(scalar::Real, sv::SecureVector) = add(sv, scalar)

# Subtract
Base.:-(sv1::SecureVector, sv2::SecureVector) = subtract(sv1, sv2)
Base.:-(sv::SecureVector, pv::PlainVector) = subtract(sv, pv)
Base.:-(pv::PlainVector, sv::SecureVector) = subtract(pv, sv)
Base.:-(sv::SecureVector, scalar::Real) = subtract(sv, scalar)
Base.:-(scalar::Real, sv::SecureVector) = subtract(scalar, sv)

# Negate
Base.:-(sv::SecureVector) = negate(sv)

# Multiply
Base.:*(sv1::SecureVector, sv2::SecureVector) = multiply(sv1, sv2)
Base.:*(sv::SecureVector, pv::PlainVector) = multiply(sv, pv)
Base.:*(pv::PlainVector, sv::SecureVector) = multiply(sv, pv)
Base.:*(sv::SecureVector, scalar::Real) = multiply(sv, scalar)
Base.:*(scalar::Real, sv::SecureVector) = multiply(sv, scalar)

# Circular shift
"""
    circshift(sv::SecureVector, shift; wrap_by = :capacity)

Circularly shift, i.e., rotate the data in `sv` by `shift` positions, similarly to Julia's
`circshift` for regular arrays. `wrap_by` indicates whether the rotation should be applied
with respect to the current data length of `sv` (`wrap_by :length`) or with respect to its
maximum capacity (`wrap_by = :capacity`).

Note: If `sv`'s length is less than its capacity, wrapping by `:length` increases the
multiplicative depth of your algorithm by one and is more expensive to compute. Furthermore,
one additional rotation is applied with a shift of
`-sign(shift) * (length(sv) - abs(shift))`.

See also: [`SecureVector`](@ref), [`length`](@ref), [`capacity`](@ref)
"""
function Base.circshift(sv::SecureVector, shift::Integer; wrap_by = :capacity)
    if !(wrap_by in (:length, :capacity))
        throw(ArgumentError("Unsupported value '$wrap_by' passed to `wrap_by` (must be `:length` or `:capacity`)"))
    end

    if shift == 0
        return sv
    end

    rotate(sv, shift; wrap_by)
end

# Add
Base.:+(sm1::SecureMatrix, sm2::SecureMatrix) = add(sm1, sm2)
Base.:+(sm::SecureMatrix, pm::PlainMatrix) = add(sm, pm)
Base.:+(pm::PlainMatrix, sm::SecureMatrix) = add(sm, pm)
Base.:+(sm::SecureMatrix, scalar::Real) = add(sm, scalar)
Base.:+(scalar::Real, sm::SecureMatrix) = add(sm, scalar)
Base.:+(sm::SecureMatrix, sv::SecureVector) = add(sm, sv)
Base.:+(sv::SecureVector, sm::SecureMatrix) = add(sm, sv)
Base.:+(sm::SecureMatrix, pv::PlainVector) = add(sm, pv)
Base.:+(pv::PlainVector, sm::SecureMatrix) = add(sm, pv)

# Subtract
Base.:-(sm1::SecureMatrix, sm2::SecureMatrix) = subtract(sm1, sm2)
Base.:-(sm::SecureMatrix, pm::PlainMatrix) = subtract(sm, pm)
Base.:-(pm::PlainMatrix, sm::SecureMatrix) = subtract(pm, sm)
Base.:-(sm::SecureMatrix, scalar::Real) = subtract(sm, scalar)
Base.:-(scalar::Real, sm::SecureMatrix) = subtract(scalar, sm)
Base.:-(sm::SecureMatrix, sv::SecureVector) = subtract(sm, sv)
Base.:-(sv::SecureVector, sm::SecureMatrix) = subtract(sv, sm)
Base.:-(sm::SecureMatrix, pv::PlainVector) = subtract(sm, pv)
Base.:-(pv::PlainVector, sm::SecureMatrix) = subtract(pv, sm)

# Negate
Base.:-(sm::SecureMatrix) = negate(sm)

# Multiply
Base.:*(sm1::SecureMatrix, sm2::SecureMatrix) = multiply(sm1, sm2)
Base.:*(sm::SecureMatrix, pm::PlainMatrix) = multiply(sm, pm)
Base.:*(pm::PlainMatrix, sm::SecureMatrix) = multiply(sm, pm)
Base.:*(sm::SecureMatrix, scalar::Real) = multiply(sm, scalar)
Base.:*(scalar::Real, sm::SecureMatrix) = multiply(sm, scalar)
Base.:*(sm::SecureMatrix, sv::SecureVector) = multiply(sm, sv)
Base.:*(sv::SecureVector, sm::SecureMatrix) = multiply(sm, sv)
Base.:*(sm::SecureMatrix, pv::PlainVector) = multiply(sm, pv)
Base.:*(pv::PlainVector, sm::SecureMatrix) = multiply(sm, pv)

# circular shift

function Base.circshift(sm::SecureMatrix, shift::Union{Vector{Int}, Tuple{Int, Int}}; wrap_by = :capacity)
    if !(wrap_by in (:length, :capacity))
        throw(ArgumentError("Unsupported value '$wrap_by' passed to `wrap_by` (must be `:length` or `:capacity`)"))
    end

    if shift[1] == 0 && shift[2] == 0
        return sm
    end

    rotate(sm, shift; wrap_by)
end