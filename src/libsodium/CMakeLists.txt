set(lib_name sodium)
############################################################
set(root_srcs
  CMakeLists.txt
  Makefile.am
  Makefile.in
  )
source_group("" FILES ${root_srcs})
list(APPEND ${lib_name}_libsrcs ${root_srcs})
############################################################
set(crypto_aead_aes256gcm_aesni_srcs
  crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c
  )
source_group(crypto_aead\\aes256gcm\\aesni FILES ${crypto_aead_aes256gcm_aesni_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_aead_aes256gcm_aesni_srcs})
###############
set(crypto_aead_chacha20poly1305_sodium_srcs
  crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
  )
source_group(crypto_aead\\chacha20poly1305\\sodium FILES ${crypto_aead_chacha20poly1305_sodium_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_aead_chacha20poly1305_sodium_srcs})
###############
set(crypto_aead_xchacha20poly1305_sodium_srcs
  crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
  )
source_group(crypto_aead\\xchacha20poly1305\\sodium FILES ${crypto_aead_xchacha20poly1305_sodium_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_aead_xchacha20poly1305_sodium_srcs})
############################################################
set(crypto_auth_srcs
  crypto_auth/crypto_auth.c
  )
source_group(crypto_auth FILES ${crypto_auth_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_auth_srcs})
###############
set(crypto_auth_hmacsha256_srcs
  crypto_auth/hmacsha256/auth_hmacsha256.c
  )
source_group(crypto_auth\\hmacsha256 FILES ${crypto_auth_hmacsha256_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_auth_hmacsha256_srcs})
###############
set(crypto_auth_hmacsha512_srcs
  crypto_auth/hmacsha512/auth_hmacsha512.c
  )
source_group(crypto_auth\\hmacsha512 FILES ${crypto_auth_hmacsha512_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_auth_hmacsha512_srcs})
###############
set(crypto_auth_hmacsha512256_srcs
  crypto_auth/hmacsha512256/auth_hmacsha512256.c
  )
source_group(crypto_auth\\hmacsha512256 FILES ${crypto_auth_hmacsha512256_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_auth_hmacsha512256_srcs})
############################################################
set(crypto_box_srcs
  crypto_box/crypto_box.c
  crypto_box/crypto_box_easy.c
  crypto_box/crypto_box_seal.c
  )
source_group(crypto_box FILES ${crypto_box_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_box_srcs})
###############
set(crypto_box_curve25519xchacha20poly1305_srcs
  crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c
  crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.c
  )
source_group(crypto_box\\curve25519xchacha20poly1305 FILES ${crypto_box_curve25519xchacha20poly1305_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_box_curve25519xchacha20poly1305_srcs})
###############
set(crypto_box_curve25519xsalsa20poly1305_srcs
  crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c
  )
source_group(crypto_box\\curve25519xsalsa20poly1305 FILES ${crypto_box_curve25519xsalsa20poly1305_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_box_curve25519xsalsa20poly1305_srcs})
############################################################
set(crypto_core_ed25519_srcs
  crypto_core/ed25519/core_ed25519.c
  crypto_core/ed25519/core_ristretto255.c
  )
source_group(crypto_core\\ed25519 FILES ${crypto_core_ed25519_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_ed25519_srcs})
###############
set(crypto_core_ed25519_ref10_srcs
  crypto_core/ed25519/ref10/ed25519_ref10.c
  )
source_group(crypto_core\\ed25519\\ref10 FILES ${crypto_core_ed25519_ref10_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_ed25519_ref10_srcs})
###############
set(crypto_core_ed25519_ref10_fe_25_5_srcs
  crypto_core/ed25519/ref10/fe_25_5/base.h
  crypto_core/ed25519/ref10/fe_25_5/base2.h
  crypto_core/ed25519/ref10/fe_25_5/constants.h
  crypto_core/ed25519/ref10/fe_25_5/fe.h
  )
source_group(crypto_core\\ed25519\\ref10\\fe_25_5 FILES ${crypto_core_ed25519_ref10_fe_25_5_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_ed25519_ref10_fe_25_5_srcs})
###############
set(crypto_core_ed25519_ref10_fe_51_srcs
  crypto_core/ed25519/ref10/fe_51/base.h
  crypto_core/ed25519/ref10/fe_51/base2.h
  crypto_core/ed25519/ref10/fe_51/constants.h
  crypto_core/ed25519/ref10/fe_51/fe.h
  )
source_group(crypto_core\\ed25519\\ref10\\fe_51 FILES ${crypto_core_ed25519_ref10_fe_51_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_ed25519_ref10_fe_51_srcs})
###############
set(crypto_core_hchacha20_srcs
  crypto_core/hchacha20/core_hchacha20.c
  )
source_group(crypto_core\\hchacha20 FILES ${crypto_core_hchacha20_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_hchacha20_srcs})
###############
set(crypto_core_hsalsa20_srcs
  crypto_core/hsalsa20/core_hsalsa20.c
  )
source_group(crypto_core\\hsalsa20 FILES ${crypto_core_hsalsa20_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_hsalsa20_srcs})
###############
set(crypto_core_hsalsa20_ref2_srcs
  crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c
  )
source_group(crypto_core\\hsalsa20\\ref2 FILES ${crypto_core_hsalsa20_ref2_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_hsalsa20_ref2_srcs})
###############
set(crypto_core_salsa_ref_srcs
  crypto_core/salsa/ref/core_salsa_ref.c
  )
source_group(crypto_core\\salsa\\ref FILES ${crypto_core_salsa_ref_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_core_salsa_ref_srcs})
############################################################
set(crypto_generichash_srcs
  crypto_generichash/crypto_generichash.c
  )
source_group(crypto_generichash FILES ${crypto_generichash_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_generichash_srcs})
###############
set(crypto_generichash_blake2b_srcs
  crypto_generichash/blake2b/generichash_blake2.c
  )
source_group(crypto_generichash\\blake2b FILES ${crypto_generichash_blake2b_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_generichash_blake2b_srcs})
###############
set(crypto_generichash_blake2b_ref_srcs
  crypto_generichash/blake2b/ref/blake2.h
  crypto_generichash/blake2b/ref/blake2b-compress-avx2.c
  crypto_generichash/blake2b/ref/blake2b-compress-avx2.h
  crypto_generichash/blake2b/ref/blake2b-compress-ref.c
  crypto_generichash/blake2b/ref/blake2b-compress-sse41.c
  crypto_generichash/blake2b/ref/blake2b-compress-sse41.h
  crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c
  crypto_generichash/blake2b/ref/blake2b-compress-ssse3.h
  crypto_generichash/blake2b/ref/blake2b-load-avx2.h
  crypto_generichash/blake2b/ref/blake2b-load-sse2.h
  crypto_generichash/blake2b/ref/blake2b-load-sse41.h
  crypto_generichash/blake2b/ref/blake2b-ref.c
  crypto_generichash/blake2b/ref/generichash_blake2b.c
  )
source_group(crypto_generichash\\blake2b\\ref FILES ${crypto_generichash_blake2b_ref_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_generichash_blake2b_ref_srcs})
############################################################
set(crypto_hash_srcs
  crypto_hash/crypto_hash.c
  )
source_group(crypto_hash FILES ${crypto_hash_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_hash_srcs})
###############
set(crypto_hash_sha256_srcs
  crypto_hash/sha256/hash_sha256.c
  )
source_group(crypto_hash\\sha256 FILES ${crypto_hash_sha256_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_hash_sha256_srcs})
###############
set(crypto_hash_sha256_cp_srcs
  crypto_hash/sha256/cp/hash_sha256_cp.c
  )
source_group(crypto_hash\\sha256\\cp FILES ${crypto_hash_sha256_cp_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_hash_sha256_cp_srcs})
###############
set(crypto_hash_sha512_srcs
  crypto_hash/sha512/hash_sha512.c
  )
source_group(crypto_hash\\sha512 FILES ${crypto_hash_sha512_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_hash_sha512_srcs})
###############
set(crypto_hash_sha512_cp_srcs
  crypto_hash/sha512/cp/hash_sha512_cp.c
  )
source_group(crypto_hash\\sha512\\cp FILES ${crypto_hash_sha512_cp_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_hash_sha512_cp_srcs})
############################################################
set(crypto_kdf_srcs
  crypto_kdf/crypto_kdf.c
  )
source_group(crypto_kdf FILES ${crypto_kdf_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_kdf_srcs})
###############
set(crypto_kdf_blake2b_srcs
  crypto_kdf/blake2b/kdf_blake2b.c
  )
source_group(crypto_kdf\\blake2b FILES ${crypto_kdf_blake2b_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_kdf_blake2b_srcs})
############################################################
set(crypto_kx_srcs
  crypto_kx/crypto_kx.c
  )
source_group(crypto_kx FILES ${crypto_kx_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_kx_srcs})
############################################################
set(crypto_onetimeauth_srcs
  crypto_onetimeauth/crypto_onetimeauth.c
  )
source_group(crypto_onetimeauth FILES ${crypto_onetimeauth_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_onetimeauth_srcs})
###############
set(crypto_onetimeauth_poly1305_srcs
  crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
  crypto_onetimeauth/poly1305/onetimeauth_poly1305.h
  )
source_group(crypto_onetimeauth\\poly1305 FILES ${crypto_onetimeauth_poly1305_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_onetimeauth_poly1305_srcs})
###############
set(crypto_onetimeauth_poly1305_donna_srcs
  crypto_onetimeauth/poly1305/donna/poly1305_donna.c
  crypto_onetimeauth/poly1305/donna/poly1305_donna.h
  crypto_onetimeauth/poly1305/donna/poly1305_donna32.h
  crypto_onetimeauth/poly1305/donna/poly1305_donna64.h
  )
source_group(crypto_onetimeauth\\poly1305\\donna FILES ${crypto_onetimeauth_poly1305_donna_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_onetimeauth_poly1305_donna_srcs})
###############
set(crypto_onetimeauth_poly1305_sse2_srcs
  crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c
  crypto_onetimeauth/poly1305/sse2/poly1305_sse2.h
  )
source_group(crypto_onetimeauth\\poly1305\\sse2 FILES ${crypto_onetimeauth_poly1305_sse2_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_onetimeauth_poly1305_sse2_srcs})
############################################################
set(crypto_pwhash_srcs
  crypto_pwhash/crypto_pwhash.c
  )
source_group(crypto_pwhash FILES ${crypto_pwhash_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_pwhash_srcs})
###############
set(crypto_pwhash_argon2_srcs
  crypto_pwhash/argon2/argon2-core.c
  crypto_pwhash/argon2/argon2-core.h
  crypto_pwhash/argon2/argon2-encoding.c
  crypto_pwhash/argon2/argon2-encoding.h
  crypto_pwhash/argon2/argon2-fill-block-avx2.c
  crypto_pwhash/argon2/argon2-fill-block-avx512f.c
  crypto_pwhash/argon2/argon2-fill-block-ref.c
  crypto_pwhash/argon2/argon2-fill-block-ssse3.c
  crypto_pwhash/argon2/argon2.c
  crypto_pwhash/argon2/argon2.h
  crypto_pwhash/argon2/blake2b-long.c
  crypto_pwhash/argon2/blake2b-long.h
  crypto_pwhash/argon2/blamka-round-avx2.h
  crypto_pwhash/argon2/blamka-round-avx512f.h
  crypto_pwhash/argon2/blamka-round-ref.h
  crypto_pwhash/argon2/blamka-round-ssse3.h
  crypto_pwhash/argon2/pwhash_argon2i.c
  crypto_pwhash/argon2/pwhash_argon2id.c
  )
source_group(crypto_pwhash\\argon2 FILES ${crypto_pwhash_argon2_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_pwhash_argon2_srcs})
###############
set(crypto_pwhash_scryptsalsa208sha256_srcs
  crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c
  crypto_pwhash/scryptsalsa208sha256/crypto_scrypt.h
  crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c
  crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.h
  crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c
  crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c
  )
source_group(crypto_pwhash\\scryptsalsa208sha256 FILES ${crypto_pwhash_scryptsalsa208sha256_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_pwhash_scryptsalsa208sha256_srcs})
###############
set(crypto_pwhash_scryptsalsa208sha256_nosse_srcs
  crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
  )
source_group(crypto_pwhash\\scryptsalsa208sha256\\nosse FILES ${crypto_pwhash_scryptsalsa208sha256_nosse_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_pwhash_scryptsalsa208sha256_nosse_srcs})
###############
set(crypto_pwhash_scryptsalsa208sha256_sse_srcs
  crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c
  )
source_group(crypto_pwhash\\scryptsalsa208sha256\\sse FILES ${crypto_pwhash_scryptsalsa208sha256_sse_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_pwhash_scryptsalsa208sha256_sse_srcs})
############################################################
set(crypto_scalarmult_srcs
  crypto_scalarmult/crypto_scalarmult.c
  )
source_group(crypto_scalarmult FILES ${crypto_scalarmult_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_scalarmult_srcs})
###############
set(crypto_scalarmult_curve25519_srcs
  crypto_scalarmult/curve25519/scalarmult_curve25519.c
  crypto_scalarmult/curve25519/scalarmult_curve25519.h
  )
source_group(crypto_scalarmult\\curve25519 FILES ${crypto_scalarmult_curve25519_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_scalarmult_curve25519_srcs})
###############
set(crypto_scalarmult_curve25519_ref10_srcs
  crypto_scalarmult/curve25519/ref10/x25519_ref10.c
  crypto_scalarmult/curve25519/ref10/x25519_ref10.h
  )
source_group(crypto_scalarmult\\curve25519\\ref10 FILES ${crypto_scalarmult_curve25519_ref10_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_scalarmult_curve25519_ref10_srcs})
###############
set(crypto_scalarmult_curve25519_sandy2x_srcs
  crypto_scalarmult/curve25519/sandy2x/consts.S
  crypto_scalarmult/curve25519/sandy2x/consts_namespace.h
  crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c
  crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.h
  crypto_scalarmult/curve25519/sandy2x/fe.h
  crypto_scalarmult/curve25519/sandy2x/fe51.h
  crypto_scalarmult/curve25519/sandy2x/fe51_invert.c
  crypto_scalarmult/curve25519/sandy2x/fe51_mul.S
  crypto_scalarmult/curve25519/sandy2x/fe51_namespace.h
  crypto_scalarmult/curve25519/sandy2x/fe51_nsquare.S
  crypto_scalarmult/curve25519/sandy2x/fe51_pack.S
  crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c
  crypto_scalarmult/curve25519/sandy2x/ladder.S
  crypto_scalarmult/curve25519/sandy2x/ladder.h
  crypto_scalarmult/curve25519/sandy2x/ladder_namespace.h
  crypto_scalarmult/curve25519/sandy2x/sandy2x.S
  )
source_group(crypto_scalarmult\\curve25519\\sandy2x FILES ${crypto_scalarmult_curve25519_sandy2x_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_scalarmult_curve25519_sandy2x_srcs})
###############
set(crypto_scalarmult_ed25519_ref10_srcs
  crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
  )
source_group(crypto_scalarmult\\ed25519\\ref10 FILES ${crypto_scalarmult_ed25519_ref10_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_scalarmult_ed25519_ref10_srcs})
###############
set(crypto_scalarmult_ristretto255_ref10_srcs
  crypto_scalarmult/ristretto255/ref10/scalarmult_ristretto255_ref10.c
  )
source_group(crypto_scalarmult\\ristretto255\\ref10 FILES ${crypto_scalarmult_ristretto255_ref10_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_scalarmult_ristretto255_ref10_srcs})
############################################################
set(crypto_secretbox_srcs
  crypto_secretbox/crypto_secretbox.c
  crypto_secretbox/crypto_secretbox_easy.c
  )
source_group(crypto_secretbox FILES ${crypto_secretbox_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_secretbox_srcs})
###############
set(crypto_secretbox_xchacha20poly1305_srcs
  crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c
  )
source_group(crypto_secretbox\\xchacha20poly1305 FILES ${crypto_secretbox_xchacha20poly1305_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_secretbox_xchacha20poly1305_srcs})
###############
set(crypto_secretbox_xsalsa20poly1305_srcs
  crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c
  )
source_group(crypto_secretbox\\xsalsa20poly1305 FILES ${crypto_secretbox_xsalsa20poly1305_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_secretbox_xsalsa20poly1305_srcs})
############################################################
set(crypto_secretstream_xchacha20poly1305_srcs
  crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c
  )
source_group(crypto_secretstream\\xchacha20poly1305 FILES ${crypto_secretstream_xchacha20poly1305_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_secretstream_xchacha20poly1305_srcs})
############################################################
set(crypto_shorthash_srcs
  crypto_shorthash/crypto_shorthash.c
  )
source_group(crypto_shorthash FILES ${crypto_shorthash_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_shorthash_srcs})
###############
set(crypto_shorthash_siphash24_srcs
  crypto_shorthash/siphash24/shorthash_siphash24.c
  crypto_shorthash/siphash24/shorthash_siphashx24.c
  )
source_group(crypto_shorthash\\siphash24 FILES ${crypto_shorthash_siphash24_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_shorthash_siphash24_srcs})
###############
set(crypto_shorthash_siphash24_ref_srcs
  crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c
  crypto_shorthash/siphash24/ref/shorthash_siphash_ref.h
  crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c
  )
source_group(crypto_shorthash\\siphash24\\ref FILES ${crypto_shorthash_siphash24_ref_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_shorthash_siphash24_ref_srcs})
############################################################
set(crypto_sign_srcs
  crypto_sign/crypto_sign.c
  )
source_group(crypto_sign FILES ${crypto_sign_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_sign_srcs})
###############
set(crypto_sign_ed25519_srcs
  crypto_sign/ed25519/sign_ed25519.c
  )
source_group(crypto_sign\\ed25519 FILES ${crypto_sign_ed25519_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_sign_ed25519_srcs})
###############
set(crypto_sign_ed25519_ref10_srcs
  crypto_sign/ed25519/ref10/keypair.c
  crypto_sign/ed25519/ref10/obsolete.c
  crypto_sign/ed25519/ref10/open.c
  crypto_sign/ed25519/ref10/sign.c
  crypto_sign/ed25519/ref10/sign_ed25519_ref10.h
  )
source_group(crypto_sign\\ed25519\\ref10 FILES ${crypto_sign_ed25519_ref10_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_sign_ed25519_ref10_srcs})
############################################################
set(crypto_stream
  crypto_stream/crypto_stream.c
  )
source_group(crypto_stream FILES ${crypto_stream})
list(APPEND ${lib_name}_libsrcs ${crypto_stream})
###############
set(crypto_stream_chacha20_srcs
  crypto_stream/chacha20/stream_chacha20.c
  crypto_stream/chacha20/stream_chacha20.h
  )
source_group(crypto_stream\\chacha20 FILES ${crypto_stream_chacha20_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_chacha20_srcs})
###############
set(crypto_stream_chacha20_dolbeau_srcs
  crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c
  crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.h
  crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c
  crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.h
  crypto_stream/chacha20/dolbeau/u0.h
  crypto_stream/chacha20/dolbeau/u1.h
  crypto_stream/chacha20/dolbeau/u4.h
  crypto_stream/chacha20/dolbeau/u8.h
  )
source_group(crypto_stream\\chacha20\\dolbeau FILES ${crypto_stream_chacha20_dolbeau_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_chacha20_dolbeau_srcs})
###############
set(crypto_stream_chacha20_ref_srcs
  crypto_stream/chacha20/ref/chacha20_ref.c
  crypto_stream/chacha20/ref/chacha20_ref.h
  )
source_group(crypto_stream\\chacha20\\ref FILES ${crypto_stream_chacha20_ref_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_chacha20_ref_srcs})
###############
set(crypto_stream_salsa20_srcs
  crypto_stream/salsa20/stream_salsa20.c
  crypto_stream/salsa20/stream_salsa20.h
  )
source_group(crypto_stream\\salsa20 FILES ${crypto_stream_salsa20_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa20_srcs})
###############
set(crypto_stream_salsa20_ref_srcs
  crypto_stream/salsa20/ref/salsa20_ref.c
  crypto_stream/salsa20/ref/salsa20_ref.h
  )
source_group(crypto_stream\\salsa20\\ref FILES ${crypto_stream_salsa20_ref_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa20_ref_srcs})
###############
set(crypto_stream_salsa20_xmm6_srcs
  crypto_stream/salsa20/xmm6/salsa20_xmm6-asm.S
  crypto_stream/salsa20/xmm6/salsa20_xmm6.c
  crypto_stream/salsa20/xmm6/salsa20_xmm6.h
  )
source_group(crypto_stream\\salsa20\\xmm6 FILES ${crypto_stream_salsa20_xmm6_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa20_xmm6_srcs})
###############
set(crypto_stream_salsa20_xmm6int_srcs
  crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c
  crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.h
  crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c
  crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.h
  crypto_stream/salsa20/xmm6int/u0.h
  crypto_stream/salsa20/xmm6int/u1.h
  crypto_stream/salsa20/xmm6int/u4.h
  crypto_stream/salsa20/xmm6int/u8.h
  )
source_group(crypto_stream\\salsa20\\xmm6int FILES ${crypto_stream_salsa20_xmm6int_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa20_xmm6int_srcs})
###############
set(crypto_stream_salsa208_srcs
  crypto_stream/salsa208/stream_salsa208.c
  )
source_group(crypto_stream\\salsa208 FILES ${crypto_stream_salsa208_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa208_srcs})
###############
set(crypto_stream_salsa208_ref_srcs
  crypto_stream/salsa208/ref/stream_salsa208_ref.c
  )
source_group(crypto_stream\\salsa208\\ref FILES ${crypto_stream_salsa208_ref_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa208_ref_srcs})
###############
set(crypto_stream_salsa2012_srcs
  crypto_stream/salsa2012/stream_salsa2012.c
  )
source_group(crypto_stream\\salsa2012 FILES ${crypto_stream_salsa2012_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa2012_srcs})
###############
set(crypto_stream_salsa2012_ref_srcs
  crypto_stream/salsa2012/ref/stream_salsa2012_ref.c
  )
source_group(crypto_stream\\salsa2012\\ref FILES ${crypto_stream_salsa2012_ref_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_salsa2012_ref_srcs})
###############
set(crypto_stream_xchacha20_srcs
  crypto_stream/xchacha20/stream_xchacha20.c
  )
source_group(crypto_stream\\xchacha20 FILES ${crypto_stream_xchacha20_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_xchacha20_srcs})
###############
set(crypto_stream_xsalsa20_srcs
  crypto_stream/xsalsa20/stream_xsalsa20.c
  )
source_group(crypto_stream\\xsalsa20 FILES ${crypto_stream_xsalsa20_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_stream_xsalsa20_srcs})
############################################################
set(crypto_verify_sodium_srcs
  crypto_verify/sodium/verify.c
  )
source_group(crypto_verify\\sodium FILES ${crypto_verify_sodium_srcs})
list(APPEND ${lib_name}_libsrcs ${crypto_verify_sodium_srcs})
############################################################
set(include_srcs
  include/Makefile.am
  include/Makefile.in
  include/sodium.h
  )
source_group(include FILES ${include_srcs})
list(APPEND ${lib_name}_libsrcs ${include_srcs})
###############
set(include_sodium_srcs
  include/sodium/core.h
  include/sodium/crypto_aead_aes256gcm.h
  include/sodium/crypto_aead_chacha20poly1305.h
  include/sodium/crypto_aead_xchacha20poly1305.h
  include/sodium/crypto_auth.h
  include/sodium/crypto_auth_hmacsha256.h
  include/sodium/crypto_auth_hmacsha512.h
  include/sodium/crypto_auth_hmacsha512256.h
  include/sodium/crypto_box.h
  include/sodium/crypto_box_curve25519xchacha20poly1305.h
  include/sodium/crypto_box_curve25519xsalsa20poly1305.h
  include/sodium/crypto_core_ed25519.h
  include/sodium/crypto_core_hchacha20.h
  include/sodium/crypto_core_hsalsa20.h
  include/sodium/crypto_core_ristretto255.h
  include/sodium/crypto_core_salsa20.h
  include/sodium/crypto_core_salsa2012.h
  include/sodium/crypto_core_salsa208.h
  include/sodium/crypto_generichash.h
  include/sodium/crypto_generichash_blake2b.h
  include/sodium/crypto_hash.h
  include/sodium/crypto_hash_sha256.h
  include/sodium/crypto_hash_sha512.h
  include/sodium/crypto_kdf.h
  include/sodium/crypto_kdf_blake2b.h
  include/sodium/crypto_kx.h
  include/sodium/crypto_onetimeauth.h
  include/sodium/crypto_onetimeauth_poly1305.h
  include/sodium/crypto_pwhash.h
  include/sodium/crypto_pwhash_argon2i.h
  include/sodium/crypto_pwhash_argon2id.h
  include/sodium/crypto_pwhash_scryptsalsa208sha256.h
  include/sodium/crypto_scalarmult.h
  include/sodium/crypto_scalarmult_curve25519.h
  include/sodium/crypto_scalarmult_ed25519.h
  include/sodium/crypto_scalarmult_ristretto255.h
  include/sodium/crypto_secretbox.h
  include/sodium/crypto_secretbox_xchacha20poly1305.h
  include/sodium/crypto_secretbox_xsalsa20poly1305.h
  include/sodium/crypto_secretstream_xchacha20poly1305.h
  include/sodium/crypto_shorthash.h
  include/sodium/crypto_shorthash_siphash24.h
  include/sodium/crypto_sign.h
  include/sodium/crypto_sign_ed25519.h
  include/sodium/crypto_sign_edwards25519sha512batch.h
  include/sodium/crypto_stream.h
  include/sodium/crypto_stream_chacha20.h
  include/sodium/crypto_stream_salsa20.h
  include/sodium/crypto_stream_salsa2012.h
  include/sodium/crypto_stream_salsa208.h
  include/sodium/crypto_stream_xchacha20.h
  include/sodium/crypto_stream_xsalsa20.h
  include/sodium/crypto_verify_16.h
  include/sodium/crypto_verify_32.h
  include/sodium/crypto_verify_64.h
  include/sodium/export.h
  include/sodium/randombytes.h
  include/sodium/randombytes_internal_random.h
  include/sodium/randombytes_sysrandom.h
  include/sodium/runtime.h
  include/sodium/utils.h
  include/sodium/version.h.in
  )
source_group(include\\sodium FILES ${include_sodium_srcs})
list(APPEND ${lib_name}_libsrcs ${include_sodium_srcs})
###############
set(include_sodium_private_srcs
  include/sodium/private/chacha20_ietf_ext.h
  include/sodium/private/common.h
  include/sodium/private/ed25519_ref10.h
  include/sodium/private/ed25519_ref10_fe_25_5.h
  include/sodium/private/ed25519_ref10_fe_51.h
  include/sodium/private/implementations.h
  include/sodium/private/mutex.h
  include/sodium/private/sse2_64_32.h
  )
source_group(include\\sodium\\private FILES ${include_sodium_private_srcs})
list(APPEND ${lib_name}_libsrcs ${include_sodium_private_srcs})
############################################################
set(randombytes_srcs
  randombytes/randombytes.c
  )
source_group(randombytes FILES ${randombytes_srcs})
list(APPEND ${lib_name}_libsrcs ${randombytes_srcs})
###############
set(randombytes_internal_srcs
  randombytes/internal/randombytes_internal_random.c
  )
source_group(randombytes\\internal FILES ${randombytes_internal_srcs})
list(APPEND ${lib_name}_libsrcs ${randombytes_internal_srcs})
###############
set(randombytes_sysrandom_srcs
  randombytes/sysrandom/randombytes_sysrandom.c
  )
source_group(randombytes\\sysrandom FILES ${randombytes_sysrandom_srcs})
list(APPEND ${lib_name}_libsrcs ${randombytes_sysrandom_srcs})
############################################################
set(sodium_srcs
  sodium/codecs.c
  sodium/core.c
  sodium/runtime.c
  sodium/utils.c
  sodium/version.c
  )
source_group(sodium FILES ${sodium_srcs})
list(APPEND ${lib_name}_libsrcs ${sodium_srcs})
############################################################
set(libsrcs ${${lib_name}_libsrcs})
if(ENABLE_MINIMAL)
  # grep "@MINIMAL_FALSE@" src/libsodium/Makefile.in
  list(REMOVE_ITEM libsrcs
    ${crypto_box_curve25519xchacha20poly1305_srcs}
    ${crypto_core_ed25519_srcs}
    ${crypto_pwhash_scryptsalsa208sha256_srcs}
    ${crypto_pwhash_scryptsalsa208sha256_nosse_srcs}
    ${crypto_pwhash_scryptsalsa208sha256_sse_srcs}
    ${crypto_scalarmult_ed25519_ref10_srcs}
    ${crypto_scalarmult_ristretto255_ref10_srcs}
    ${crypto_secretbox_xchacha20poly1305_srcs}
    crypto_shorthash/siphash24/shorthash_siphashx24.c
    crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c
    crypto_sign/ed25519/ref10/obsolete.c
    ${crypto_stream_salsa2012_srcs}
    ${crypto_stream_salsa2012_ref_srcs}
    ${crypto_stream_salsa208_srcs}
    ${crypto_stream_salsa208_ref_srcs}
    ${crypto_stream_xchacha20_srcs}
    )
endif()
############################################################
set(VERSION ${PROJECT_VERSION})
file(STRINGS ${CMAKE_SOURCE_DIR}/configure.ac configure_ac REGEX "^SODIUM_LIBRARY_VERSION_MAJOR=([0-9]+)")
string(REGEX MATCH "([0-9]+)" SODIUM_LIBRARY_VERSION_MAJOR "${configure_ac}")
file(STRINGS ${CMAKE_SOURCE_DIR}/configure.ac configure_ac REGEX "^SODIUM_LIBRARY_VERSION_MINOR=([0-9]+)")
string(REGEX MATCH "([0-9]+)" SODIUM_LIBRARY_VERSION_MINOR "${configure_ac}")
if(ENABLE_MINIMAL)
  set(SODIUM_LIBRARY_MINIMAL_DEF "#define SODIUM_LIBRARY_MINIMAL 1")
endif()
configure_file(include/sodium/version.h.in include/sodium/version.h)
############################################################
if(DEFINED XP_NAMESPACE)
  set(nameSpace NAMESPACE ${XP_NAMESPACE}::)
endif()
if(NOT DEFINED XP_INSTALL_CMAKEDIR)
  set(XP_INSTALL_CMAKEDIR ${CMAKE_INSTALL_DATADIR}/cmake)
endif()
############################################################
add_library(${lib_name} STATIC ${libsrcs})
target_compile_definitions(${lib_name} PUBLIC SODIUM_STATIC PRIVATE ${pvtDefs})
target_compile_options(${lib_name} PRIVATE ${pvtOpts})
target_include_directories(${lib_name} PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/sodium>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include/sodium
  )
target_link_libraries(${lib_name} PRIVATE Threads::Threads)
############################################################
set(targetsFile ${lib_name}-targets)
string(JOIN "\n" EXT1
  "set(THREAD_PREFER_PTHREAD_FLAG ON)"
  "find_package(Threads REQUIRED) # depends on Threads::Threads"
  ""
  )
set(lib ${lib_name})
if(DEFINED XP_NAMESPACE)
  string(PREPEND lib "${XP_NAMESPACE}::")
endif()
xpPackageDevel(TARGETS_FILE ${targetsFile} LIBRARIES ${lib})
install(DIRECTORY include/ ${CMAKE_CURRENT_BINARY_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h"
  PATTERN "private*" EXCLUDE
  )
install(TARGETS ${lib_name} EXPORT ${targetsFile}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
install(EXPORT ${targetsFile} DESTINATION ${XP_INSTALL_CMAKEDIR} ${nameSpace})
compareCmakeFilesys("${${lib_name}_libsrcs}")
