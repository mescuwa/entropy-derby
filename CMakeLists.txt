cmake_minimum_required(VERSION 3.16)

project(inside-track LANGUAGES CXX)

enable_testing()

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(Boost REQUIRED)

add_library(inside_track_engine
    src/horse.cpp
    src/race.cpp
    src/rng.cpp
    src/deterministic_math.cpp
    src/betting.cpp
    src/collaborative_rng.cpp
    src/threshold_bls_rng.cpp
    src/parimutuel.cpp
    src/secure_random.cpp
    src/transcript_log.cpp
    src/vdf.cpp
    src/race_timelock.cpp
    src/timelock_encryption.cpp
)

target_include_directories(inside_track_engine PUBLIC include)
target_include_directories(inside_track_engine PUBLIC ${SODIUM_INCLUDE_DIRS})
target_include_directories(inside_track_engine PRIVATE ${Boost_INCLUDE_DIRS})
target_link_directories(inside_track_engine PUBLIC ${SODIUM_LIBRARY_DIRS})
target_link_libraries(inside_track_engine PUBLIC ${SODIUM_LIBRARIES})

option(IT_ENABLE_BLST "Enable blst backend for threshold BLS RNG (required; RELIC backend deprecated)" OFF)

if(NOT IT_ENABLE_BLST)
    message(FATAL_ERROR "ThresholdBlsRng now requires the blst backend. The RELIC backend has been deprecated and is no longer supported.")
endif()

if(IT_ENABLE_BLST)
    find_path(BLST_INCLUDE_DIR blst.h)
    find_library(BLST_LIBRARY NAMES blst)
    if(BLST_INCLUDE_DIR AND BLST_LIBRARY)
        target_include_directories(inside_track_engine PRIVATE ${BLST_INCLUDE_DIR})
        target_link_libraries(inside_track_engine PRIVATE ${BLST_LIBRARY})
        target_compile_definitions(inside_track_engine PRIVATE IT_ENABLE_BLST)
    else()
        message(FATAL_ERROR "IT_ENABLE_BLST is ON but blst headers/libraries were not found")
    endif()
endif()

add_executable(inside_track_cli src/main.cpp)
target_link_libraries(inside_track_cli PRIVATE inside_track_engine)

add_executable(generate_seeds tools/generate_seeds.cpp)
target_link_libraries(generate_seeds PRIVATE inside_track_engine)

add_executable(analyze_config tools/analyze_config.cpp)
target_link_libraries(analyze_config PRIVATE inside_track_engine)

add_executable(audit_race tools/audit_race.cpp)
target_link_libraries(audit_race PRIVATE inside_track_engine)

add_executable(publish_log tools/publish_log.cpp)
target_link_libraries(publish_log PRIVATE inside_track_engine)

add_executable(sim_determinism tests/determinism.cpp)
target_link_libraries(sim_determinism PRIVATE inside_track_engine)

add_executable(race_timelock_test tests/test_race_timelock.cpp)
target_link_libraries(race_timelock_test PRIVATE inside_track_engine)
add_test(NAME race_timelock COMMAND race_timelock_test)

option(ENABLE_GMP_BENCHMARK "Enable GMP comparison in VDF benchmark" OFF)
if(ENABLE_GMP_BENCHMARK)
    find_package(GMP REQUIRED)
    add_compile_definitions(IT_ENABLE_GMP_BENCH)
endif()

add_executable(bench_vdf tools/bench_vdf.cpp)
target_link_libraries(bench_vdf PRIVATE inside_track_engine)
if(ENABLE_GMP_BENCHMARK)
    if(TARGET GMP::gmpxx)
        target_link_libraries(bench_vdf PRIVATE GMP::gmpxx)
    else()
        target_include_directories(bench_vdf PRIVATE ${GMP_INCLUDE_DIR})
        target_link_libraries(bench_vdf PRIVATE ${GMPXX_LIBRARIES} ${GMP_LIBRARIES})
    endif()
endif()
