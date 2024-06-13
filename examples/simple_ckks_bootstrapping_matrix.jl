using SecureArithmetic
using OpenFHE

# Note: this is a significantly truncated version of the original
# `simple_ckks_bootstrapping.jl` example in OpenFHE.jl, due to some of the properties (such
# as creating a packed plaintext with additional properties) not yet being sufficiently
# generalized.
function simple_ckks_bootstrapping_matrix(context)
    public_key, private_key = generate_keys(context)

    init_multiplication!(context, private_key)
    init_bootstrapping!(context, private_key)

    x = [[0.25, 0.5, 0.75], [1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]

    pm = PlainMatrix(x, context)
    println("Input: ", pm)

    sm = encrypt(pm, public_key)

    # Perform the bootstrapping operation. The goal is to increase the number of levels
    # remaining for HE computation.
    sm_after = bootstrap!(sm)

    result = decrypt(sm, private_key)
    println("Output after bootstrapping \n\t", result)
end


################################################################################
println("="^80)
println("Creating OpenFHE context...")

parameters = CCParams{CryptoContextCKKSRNS}()

secret_key_distribution = UNIFORM_TERNARY
SetSecretKeyDist(parameters, secret_key_distribution)

SetSecurityLevel(parameters, HEStd_NotSet)
SetRingDim(parameters, 1 << 12)

rescale_technique = FLEXIBLEAUTO
dcrt_bits = 59
first_modulus = 60

SetScalingModSize(parameters, dcrt_bits)
SetScalingTechnique(parameters, rescale_technique)
SetFirstModSize(parameters, first_modulus)

level_budget = [4, 4]

levels_available_after_bootstrap = 10
depth = levels_available_after_bootstrap + GetBootstrapDepth(level_budget, secret_key_distribution)
SetMultiplicativeDepth(parameters, depth)

cc = GenCryptoContext(parameters)

Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)
Enable(cc, ADVANCEDSHE)
Enable(cc, FHE)

ring_dimension = GetRingDimension(cc)
# This is the maximum number of slots that can be used for full packing.
num_slots = div(ring_dimension,  2)
println("CKKS scheme is using ring dimension ", ring_dimension)
println()

EvalBootstrapSetup(cc; level_budget)

context_openfhe = SecureContext(OpenFHEBackend(cc))


################################################################################
println("="^80)
println("Creating unencrypted context...")
println()

context_unencrypted = SecureContext(Unencrypted())


################################################################################
println("="^80)
println("simple_ckks_bootstrapping_matrix with an OpenFHE context")
simple_ckks_bootstrapping_matrix(context_openfhe)


################################################################################
println("="^80)
println("simple_ckks_bootstrapping_matrix with an Unencrypted context")
simple_ckks_bootstrapping_matrix(context_unencrypted)
