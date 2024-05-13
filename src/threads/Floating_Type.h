#ifndef FLOATING_H
#define FLOATING_H
#include <stdint.h>

#define F 16384 // 2^14

typedef int Floating_t;

int Int_to_Fix(int a);
int Fix_to_Int(int a);
int Int_Round(int a);
int Add_Fix_to_Int(int a, int b);
int Add_Fix(int a, int b);
int Sub_Fix_and_Int(int a, int b);
int Sub_Fix(int a, int b);
int Mul_Fix_with_Int(int a, int b);
int Mul_Fix(int a, int b);
int Div_Fix_Int(int a, int b);
int Div_Fix(int a, int b);

int Int_to_Fix(int a)
{
	return a * F;
}

int Fix_to_Int(int a)
{
	return a / F;
}

int Int_Round(int a)
{
	if (a>=0)
		return (a + F/2) / F;
	else
		return (a - F/2) / F;
}

int Add_Fix_to_Int(int a, int b)
{
	return a + (b * F);
}

int Add_Fix(int a, int b)
{
	return a + b;
}

int Sub_Fix_and_Int(int a, int b)
{
	return a - (b * F);
}

int Sub_Fix(int a, int b)
{
	return a - b;
}

int Mul_Fix_with_Int(int a, int b)
{
	return a * b;
}

int Mul_Fix(int a, int b)
{
	return ((int64_t) a) * b / F;
}

int Div_Fix_Int(int a, int b)
{
	return a / b;
}

int Div_Fix(int a, int b)
{
	return ((int64_t) a) * F / b;
}

#endif