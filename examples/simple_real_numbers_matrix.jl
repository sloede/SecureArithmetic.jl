using SecureArithmetic
using OpenFHE

function simple_real_numbers_matrix(context)
    public_key, private_key = generate_keys(context)

    init_multiplication!(context, private_key)
    init_rotation!(context, private_key, [-1, 2])


    x1 = [[0.25, 0.5, 0.75], [1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]
    x2 = [6.0 5.0 4.0; 3.0 2.0 1.0; 0.75 0.5 0.25]

    pm1 = PlainMatrix(x1, context)
    pm2 = PlainMatrix(x2, context)

    println("Input x1: ", pm1)
    println("Input x2: ", pm2)

    sm1 = encrypt(pm1, public_key)
    sm2 = encrypt(pm2, public_key)

    sm_add = sm1 + sm2

    sm_sub = sm1 - sm2

    sm_scalar = sm1 * 4.0

    sm_mult = sm1 * sm2

    sm_shift1 = circshift(sm1, (-1, 1))
    sm_shift2 = circshift(sm1, (2, 1), wrap_by=:length)


    println()
    println("Results of homomorphic computations: ")

    result_sm1 = decrypt(sm1, private_key)
    println("x1 = ", result_sm1)

    result_sm_add = decrypt(sm_add, private_key)
    println("x1 + x2 = ", result_sm_add)

    result_sm_sub = decrypt(sm_sub, private_key)
    println("x1 - x2 = ", result_sm_sub)

    result_sm_scalar = decrypt(sm_scalar, private_key)
    println("4 * x1 = ", result_sm_scalar)

    result_sm_mult = decrypt(sm_mult, private_key)
    println("x1 * x2 = ", result_sm_mult)

    result_sm_shift1 = decrypt(sm_shift1, private_key)
    println("x1 shifted circularly by (-1,1) = ", result_sm_shift1)

    result_sm_shift2 = decrypt(sm_shift2, private_key)
    println("x1 shifted circularly by (2,1), wrapped by length = ", result_sm_shift2)
end


################################################################################
println("="^80)
println("Creating OpenFHE context...")

multiplicative_depth = 1
scaling_modulus = 50
batch_size = 8

parameters = CCParams{CryptoContextCKKSRNS}()
SetMultiplicativeDepth(parameters, multiplicative_depth)
SetScalingModSize(parameters, scaling_modulus)
SetBatchSize(parameters, batch_size)

cc = GenCryptoContext(parameters)
Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)
println("CKKS scheme is using ring dimension ", GetRingDimension(cc))
println()

context_openfhe = SecureContext(OpenFHEBackend(cc))


################################################################################
println("="^80)
println("Creating unencrypted context...")
println()

context_unencrypted = SecureContext(Unencrypted())


################################################################################
println("="^80)
println("simple_real_numbers_matrix with an OpenFHE context")
simple_real_numbers_matrix(context_openfhe)
println()


################################################################################
println("="^80)
println("simple_real_numbers_matrix with an Unencrypted context")
simple_real_numbers_matrix(context_unencrypted)

