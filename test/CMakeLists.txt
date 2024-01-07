# test/CMakeLists.txt
find_package(GTest REQUIRED)

include_directories(${GTEST_INCLUDE_DIRS})

add_executable(calculator_test calculator_test.cpp)
target_link_libraries(calculator_test calculator_lib ${GTEST_LIBRARIES} pthread)

