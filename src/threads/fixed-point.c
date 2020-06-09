#include "threads/thread.h"

#define DEC_NUM 14
#define DEC_UNIT (1 << DEC_NUM)
#define DEC_UNIT2 (1 << (DEC_NUM-1))

dec int_to_dec (int n) { return n * DEC_UNIT; }
int dec_to_int (dec x) { return x / DEC_UNIT; }

dec dec_add (dec x, dec y) { return x + y; }
dec dec_sub (dec x, dec y) { return x - y; }
dec dec_mul (dec x, dec y) { return ((long long) x * y) / DEC_UNIT; }
dec dec_div (dec x, dec y) { return ((long long) x * DEC_UNIT) / y; }

dec dec_add_int (dec x, int n) { return x + n * DEC_UNIT; }
dec dec_sub_int (dec x, int n) { return x - n * DEC_UNIT; }
dec dec_mul_int (dec x, int n) { return x * n; }
dec dec_div_int (dec x, int n) { return x / n; }
