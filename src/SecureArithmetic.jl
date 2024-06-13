module SecureArithmetic

using OpenFHE: OpenFHE

# Basic types
export SecureContext, SecureVector, PlainVector, SecureMatrix, PlainMatrix

# Keys
export PrivateKey, PublicKey

# Backends
export Unencrypted, OpenFHEBackend

# Crypto operations
export generate_keys, init_multiplication!, init_rotation!, init_bootstrapping!
export encrypt, decrypt, decrypt!, bootstrap!

# Query crypto objects
export level, capacity

include("types.jl")
include("operations.jl")
include("openfhe.jl")
include("unencrypted.jl")
include("arithmetic.jl")

end # module SecureArithmetic
