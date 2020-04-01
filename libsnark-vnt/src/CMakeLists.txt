include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

################
# 生成链接库
################
#shared library

add_library(
  zk_convert
  SHARED
  convert/convertcgo.cpp
)

add_library(
  zk_claim
  SHARED
  claim/claimcgo.cpp
)

add_library(
  zk_deposit_sg
  SHARED
  deposit_sg/deposit_sgcgo.cpp
)

# add_library(
#   zk_mint
#   SHARED
#   mint/mintcgo.cpp
# )

# add_library(
#   zk_commit
#   SHARED
#   commit/commitcgo.cpp
# )

###############################
# 生成各个gadget的所需的pk，vk
###############################
add_executable(
  convert_key

  convert/getpvk.cpp
)

target_link_libraries(
  convert_key

  snark
)

target_include_directories(
  convert_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

##################################
add_executable(
  claim_key

  claim/getpvk.cpp
)

target_link_libraries(
  claim_key

  snark
)

target_include_directories(
  claim_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

###################################
add_executable(
  deposit_sg_key

  deposit_sg/getpvk.cpp
)

target_link_libraries(
  deposit_sg_key

  snark
)

target_include_directories(
  deposit_sg_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

###################################
# add_executable(
#   mint_key

#   mint/getpvk.cpp
# )

# target_link_libraries(
#   mint_key

#   snark
# )

# target_include_directories(
#   mint_key

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )

# #########################
# add_executable(
#   send_key

#   send/getpvk.cpp
# )

# target_link_libraries(
#   send_key

#   snark
# )

# target_include_directories(
#   send_key

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )

# #########################
# add_executable(
#   deposit_key

#   deposit/getpvk.cpp
# )

# target_link_libraries(
#   deposit_key

#   snark
# )

# target_include_directories(
#   deposit_key

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )

# #########################
# add_executable(
#   redeem_key

#   redeem/getpvk.cpp
# )

# target_link_libraries(
#   redeem_key

#   snark
# )

# target_include_directories(
#   redeem_key

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )

# #########################
# add_executable(
#   commit_key

#   commit/getpvk.cpp
# )

# target_link_libraries(
#   commit_key

#   snark
# )

# target_include_directories(
#   commit_key

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )