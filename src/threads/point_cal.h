#ifndef POINT_CAL_H
#define POINT_CAL_H

#include <stdint.h>
#include <stddef.h>

typedef int fixed_point; // 定义定点数类型
#define F 16             // 定义定点数的位数（直接用 14）

// 优化后的宏实现
#define INT_TO_FP(n) ((n) << F)                              // 整数转定点数，左移 F 位
#define FP_TO_INT_ZERO(x) ((x) >> F)                         // 定点数转整数，向零取整，右移 F 位
#define FP_TO_INT_NEAREST(x) (((x) + ((x) >= 0 ? (1 << (F - 1)) : -(1 << (F - 1)))) >> F) // 定点数转整数，四舍五入
#define ADD(x, y) ((x) + (y))                                // 两个定点数相加
#define SUB(x, y) ((x) - (y))                                // 两个定点数相减
#define ADD_N(x, n) ((x) + ((n) << F))                       // 定点数加整数
#define SUB_N(x, n) ((x) - ((n) << F))                       // 定点数减整数

// 优化乘法和除法
#define MUL(x, y) ((fixed_point)(((int64_t)(x) * (y)) >> F))  // 两个定点数相乘，结果右移 F 位
#define MUL_N(x, n) ((x) * (n))                               // 定点数乘整数
#define DIV(x, y) ((fixed_point)(((int64_t)(x) << F) / (y)))  // 两个定点数相除，分子左移 F 位
#define DIV_N(x, n) ((x) / (n))                               // 定点数除以整数

#endif // POINT_CAL_H
