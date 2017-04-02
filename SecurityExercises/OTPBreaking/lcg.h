// A trivial implementation of LCG. Use it just for studying or fun.
#ifndef LCG
#define LCG

unsigned int x_curr = 0; /* just to compile; it isn't the key */
unsigned int x_next;
unsigned int a = 1103515245;
unsigned int c = 12345;
unsigned int m = 1 << 31;

void my_srand(unsigned seed)
{
	x_curr = seed;
}

int my_rand()
{
	x_next = (x_curr * a + c) % m;
	x_curr = x_next;
	return x_next;
}

#endif // !LCG