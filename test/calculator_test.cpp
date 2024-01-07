// test/calculator_test.cpp
#include <gtest/gtest.h>
#include "../src/calculator.h"

TEST(CalculatorTest, Addition) {
    Calculator calculator;
    EXPECT_EQ(calculator.add(2, 3), 5); // 预期 2 + 3 = 5
    EXPECT_EQ(calculator.add(-2, 3), 1); // 预期 -2 + 3 = 1
    EXPECT_EQ(calculator.add(0, 0), 0);  // 预期 0 + 0 = 0
}

TEST(CalculatorTest, Subtraction) {
    Calculator calculator;
    EXPECT_EQ(calculator.subtract(5, 3), 2);  // 预期 5 - 3 = 2
    EXPECT_EQ(calculator.subtract(-2, -3), 1); // 预期 -2 - (-3) = 1
    EXPECT_EQ(calculator.subtract(0, 0), 0);   // 预期 0 - 0 = 0
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

