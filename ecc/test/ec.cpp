#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <ctime>
#include <cassert>
#include "ec_ops.h"
#include <vector>

using namespace std;

std::vector<int> getPrimes(int n);
void test_inverse();
void test_power();
void test_pointadd();

ECpoint operator - (const ECpoint &a, const ECpoint &b); //substraction
ECpoint operator - (const ECpoint &a);  //unary negation

Zp Zp::inverse() const{
	// Implement the Extended Euclidean Algorithm to return the inverse mod PRIME

	uberzahl a = this->value;
	if(a == "0")
	{
		cout<<"Zero has no inverse in Zp\n"<<flush;
		// abort();
		return Zp(0);
	}
	uberzahl b = PRIME;
	uberzahl  s("1");
	uberzahl ss("0");
	uberzahl  t("0");
	uberzahl tt("1");
	uberzahl q;
	uberzahl temp;
	while(b != "0")
	{
		q = a / b;

		temp = a;
		a = b;
		b = temp % b;

		temp = s;
		s = ss;
		ss = temp - ss * q;

		temp = t;
		t = tt;
		tt = temp - tt * q;
	}
		
	return Zp(s);
}


ECpoint ECpoint::operator + (const ECpoint &a) const {
	// Implement  elliptic curve addition
	if(a.infinityPoint)
		return *this;
	else if(this->infinityPoint)
		return a;
	Zp xP = this->x;
	Zp yP = this->y;
	Zp xQ = a.x;
	Zp yQ = a.y;
	Zp m;

	if(xP == xQ && yP == yQ)
	{
		if(yP == Zp(0))
			return ECpoint(true);
		m = (Zp(3) * xP * xP + Zp(A) )*(Zp(2) * yP).inverse();
	}
	else
	{
		if(xP == xQ)
			return ECpoint(true);
		m = (yQ - yP)*(xQ-xP).inverse();
	}

	Zp xR = m*m - xQ - xP;
	Zp yR = m*(xR-xP) + yP;
	return ECpoint(xR,-yR);
}

ECpoint ECpoint::repeatSum(ECpoint p, uberzahl v) const {
	//Find the sum of p+p+...+p (vtimes)
	if(p.infinityPoint)
		return p;
	else if( v < "0")
		return p.repeatSum(-p,-v);
	else
	{
		ECpoint r(true);
		while( v > "0" )
		{
			if( (v & "1") == "1")
				r =  r + p;
			p = p + p;
			v = v >> 1;
		}
		return r;
	}


}

Zp ECsystem::power(Zp val, uberzahl pow) {
	//Find the product of val*val*...*val (pow times)
	if( val == Zp(0) )
		return val;
	else if( pow < "0")
		return this->power(val.inverse(), -pow);

	Zp c = Zp(1);
	while( pow > "0" )
	{
		if( (pow & "1") == "1")
			c =  c*val;
		val = val*val;
		pow = pow >> 1;
	}
	
	return c;
}


uberzahl ECsystem::pointCompress(ECpoint e) {
	//It is the gamma function explained in the assignment.
	//Note: Here return type is mpz_class because the function may
	//map to a value greater than the defined PRIME number (i.e, range of Zp)
	//This function is fully defined.
	uberzahl compressedPoint = e.x.getValue();
	compressedPoint = compressedPoint<<1;
	if(e.infinityPoint) {
		cout<<"Point cannot be compressed as its INF-POINT"<<flush;
		abort();
		}
	else {
		if (e.y.getValue()%2 == 1)
			compressedPoint = compressedPoint + 1;
		}
		// cout<<"For point  "<<e<<"  Compressed point is "<<compressedPoint<<"\n";
		return compressedPoint;

}

ECpoint ECsystem::pointDecompress(uberzahl compressedPoint){
	//Implement the delta function for decompressing the compressed point

	Zp x = compressedPoint >> 1;
	Zp z = this->power(x,3) + Zp(A) * x + Zp(B);
	Zp y = this->power(z,(PRIME+"1")/"4");
	if( (y.getValue() % 2) != (compressedPoint % 2) )
		y = Zp(PRIME)-y;
	return ECpoint(x,y);
}


pair<pair<Zp,Zp>,uberzahl> ECsystem::encrypt(ECpoint publicKey, uberzahl privateKey,Zp plaintext0,Zp plaintext1){
	// You must implement elliptic curve encryption
	//  Do not generate a random key. Use the private key that is passed from the main function
	ECpoint Q = privateKey * G;
	ECpoint key = privateKey * this->publicKey;
	Zp ciphertext0 = plaintext0 * key.x;
	Zp ciphertext1 = plaintext1 * key.y;
	uberzahl ciphertext2 = this->pointCompress(Q);
	return make_pair(make_pair(ciphertext0,ciphertext1),ciphertext2);
}


pair<Zp,Zp> ECsystem::decrypt(pair<pair<Zp,Zp>, uberzahl> ciphertext){
	// Implement EC Decryption

	ECpoint R = this->privateKey * this->pointDecompress(ciphertext.second);
	Zp plaintext0 = ciphertext.first.first * R.x.inverse();
	Zp plaintext1 = ciphertext.first.second * R.y.inverse();
	return make_pair(plaintext0,plaintext1);
}


/*
 * main: Compute a pair of public key and private key
 *       Generate plaintext (m1, m2)
 *       Encrypt plaintext using elliptic curve encryption
 *       Decrypt ciphertext using elliptic curve decryption
 *       Should get the original plaintext
 *       Don't change anything in main.  We will use this to
 *       evaluate the correctness of your program.
 */


int main(void)
{
	clock_t begin, end;
	double time_spent;

	begin = clock();

	// std::vector<int> primes;
	// primes = getPrimes(10000);
	// cout << primes[primes.size()-1] << endl;
	test_inverse();
	test_power();
	test_pointadd();
	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	cout << "\nTIME :" << time_spent << "seconds" << endl;

	return 0;

}

std::vector<int> getPrimes(int n)
{
    std::vector<int> primes;
    primes.push_back(2);
    for(int i=3; i < n; i++)
    {
        bool prime=true;
        for(int j=0;j<primes.size() && primes[j]*primes[j] <= i;j++)
        {
            if(i % primes[j] == 0)
            {
                prime=false;
                break;
            }
        }
        if(prime)
        {
            primes.push_back(i);
            // cout << i << " ";
        }
    }

    return primes;
}

void test_inverse()
{
	for (uberzahl i("1") ; i <= PRIME;)
	{
		Zp x(i);
		Zp y = x.inverse();
		cout << x << " " << y << " " << x*y << endl;
		assert(x*y == Zp(1) || x == Zp(0));
		i = i+1;
	}
}

void test_power()
{
	ECsystem ec;
	Zp x("0");
	Zp y = ec.power(x,uberzahl("345"));
	assert(y == Zp(0));

	for (uberzahl i("1") ; i < PRIME;)
	{
		Zp x(i);
		y = ec.power(x,PRIME-"1");
		assert(y == Zp(1));
		y = ec.power(x,-(PRIME-"1"));
		cout << x << " " << y << endl;
		assert(y == Zp(1));
		i = i+"1";
	}
}

void test_pointadd()
{
	ECpoint I(true);
	ECpoint X(Zp(0),Zp(1));
	ECpoint Y(Zp(55),Zp(195));
	assert(I+I == I);
	assert(X+I == X);
	assert(I+X == X);
	assert(X+X == ECpoint(Zp(152),Zp(227)));
	assert(X+Y == ECpoint(Zp(321),Zp(239)));
	
	ECpoint G(Zp(3),Zp(387));
	X = ECpoint(true);
	for (uberzahl i("0") ; i <= ORDER;)
	{
		Y = i * G;
		cout << X << " " << Y << endl;
		assert(X == Y);
		X = X + G;
		i = i+"1";
	}
	X = ECpoint(true);
	for (uberzahl i("0") ; i <= ORDER;)
	{
		Y = (-i) * G;
		cout << X << " " << Y << endl;
		assert(X == Y);
		X = X - G;
		i = i+"1";
	}
	ECsystem ec;
	for (uberzahl i("1") ; i <= ORDER;)
	{
		Y = i * G;
		uberzahl z = ec.pointCompress(Y);
		X = ec.pointDecompress(z);
		cout << Y << " " << z << endl;
		assert(X == Y);
		i = i+"1";
	}
}


ECpoint operator - (const ECpoint &a, const ECpoint &b)
{
	return a + (-b);
}
ECpoint operator - (const ECpoint &a)
{
	if(a.infinityPoint)
	{
		return a;
	}
	return ECpoint(a.x,-a.y);

}

