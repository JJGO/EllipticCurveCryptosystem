#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <utility>
// #include <cassert>
#include "ec_ops.h"
using namespace std;

Zp Zp::inverse() const{
	// Implement the Extended Euclidean Algorithm to return the inverse mod PRIME

	uberzahl a = this->value;
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
		ss = temp - ss*q;

		temp = t;
		t = tt;
		tt = temp - tt*q;
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

ECpoint ECpoint::operator - (const ECpoint &a) const {
	return *this+(-a);
}



ECpoint ECpoint::repeatSum(ECpoint p, uberzahl v) const {
	//Find the sum of p+p+...+p (vtimes)
	if(p.infinityPoint)
		return p;
	else if( v < "0")
		return p.repeatSum(-p,-v);
	else if( v == "0")
		return ECpoint(true);
	else
	{
		ECpoint r(true);
		while( v > "0" )
		{
			if( (v & "1") == "1")
				r =  r+p;
			p = p+p;
			v = v >> 1;
		}
		return r;
	}


}

Zp ECsystem::power(Zp val, uberzahl pow) {
	//Find the product of val*val*...*val (pow times)
	Zp c = Zp(1);
	while( pow > "0" )
	{
		if( (pow & "1") == "1")
			c =  c*val;
		val = val*val;
		pow = pow >> 1;
	}
	// assert(0);
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
		//cout<<"For point  "<<e<<"  Compressed point is <<"<<compressedPoint<<"\n";
		return compressedPoint;

}

ECpoint ECsystem::pointDecompress(uberzahl compressedPoint){
	//Implement the delta function for decompressing the compressed point

	// assert(0);
	return ECpoint(true);
}


pair<pair<Zp,Zp>,uberzahl> ECsystem::encrypt(ECpoint publicKey, uberzahl privateKey,Zp plaintext0,Zp plaintext1){
	// You must implement elliptic curve encryption
	//  Do not generate a random key. Use the private key that is passed from the main function

	// assert(0);
	return make_pair(make_pair(0,0),0);
}


pair<Zp,Zp> ECsystem::decrypt(pair<pair<Zp,Zp>, uberzahl> ciphertext){
	// Implement EC Decryption

	// assert(0);
	return make_pair(0,0);
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

	// ECsystem ec;
	// unsigned long incrementVal;
	// pair <ECpoint, uberzahl> keys = ec.generateKeys();
	
	// Zp plaintext0(MESSAGE0);
	// Zp plaintext1(MESSAGE1);
	// ECpoint publicKey = keys.first;
	// cout<<"Public key is: "<<publicKey<<"\n";
	
	// cout<<"Enter offset value for sender's private key"<<endl;
	// cin>>incrementVal;
	// uberzahl privateKey = XB + incrementVal;
	
	// pair<pair<Zp,Zp>, uberzahl> ciphertext = ec.encrypt(publicKey, privateKey, plaintext0,plaintext1);
	// cout<<"Encrypted ciphertext is: ("<<ciphertext.first.first<<", "<<ciphertext.first.second<<", "<<ciphertext.second<<")\n";
	// pair<Zp,Zp> plaintext_out = ec.decrypt(ciphertext);
	
	// cout << "Original plaintext is: (" << plaintext0 << ", " << plaintext1 << ")\n";
	// cout << "Decrypted plaintext: (" << plaintext_out.first << ", " << plaintext_out.second << ")\n";


	// if(plaintext0 == plaintext_out.first && plaintext1 == plaintext_out.second)
	// 	cout << "Correct!" << endl;
	// else
	// 	cout << "Plaintext different from original plaintext." << endl;
			
	// return 1;

}


