//
// Created by yyh on 19-6-19.
//

#ifndef SRC_FIXPOINT_H
#define SRC_FIXPOINT_H

typedef int fp;

#define SFT 14

#define to_fp(x) (fp)((x)<<SFT)

#define to_int_z(x) ((x)>>SFT)

#define to_int_n(x) (((x)>=0)? (((x)+(1<<(SFT-1)))>>SFT):(((x)-(1<<(SFT-1)))>>SFT))

#define fadd(x,y) ((x)+(y))

#define fsub(x,y) ((x)-(y))

#define iadd(x,n) ((x)+((n)<<SFT))

#define isub(x,n) ((x)-((n)<<SFT))

#define fmul(x,y) (fp)((((int64_t)(x))*(y))>>SFT)

#define imul(x,n) ((x)*(n))

#define fdiv(x,y) (fp)((((int64_t)(x))<<SFT)/(y))

#define idiv(x,n) ((x)/(n))

#endif //SRC_FIXPOINT_H
