#ifndef __THREADS_FIXED_POINT_H
#define __THREADS_FIXED_POINT_H

#define dec int

dec int_to_dec (int);
int dec_to_int (dec);

dec dec_add (dec, dec);
dec dec_sub (dec, dec);
dec dec_mul (dec, dec);
dec dec_div (dec, dec);

dec dec_add_int (dec, int);
dec dec_sub_int (dec, int);
dec dec_mul_int (dec, int);
dec dec_div_int (dec, int);

#endif
