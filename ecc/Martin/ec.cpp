#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <ctime>
// #include <cassert>
#include "ec_ops.h"
using namespace std;

ECpoint operator - (const ECpoint &a, const ECpoint &b); //substraction
ECpoint operator - (const ECpoint &a);  //unary negation

Zp Zp::inverse() const{
	// Implement the Extended Euclidean Algorithm to return the inverse mod PRIME

	uberzahl a = this->value;
	if(a == "0")
	{
		cout<<"Zero has no inverse in Zp"<<flush;
		abort();
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

void run(uberzahl messagePart1, uberzahl& messagePart2, unsigned long incrementVal)
{
	clock_t begin, end;
	double time_spent;

	begin = clock();

	ECsystem ec;

	pair <ECpoint, uberzahl> keys = ec.generateKeys();
	
	Zp plaintext0(/*MESSAGE0*/messagePart1);
	Zp plaintext1(/*MESSAGE1*/messagePart2);
	ECpoint publicKey = keys.first;
	cout<<"Public key is: "<<publicKey<<"\n";
	
	cout<<"Enter offset value for sender's private key"<<endl;

	uberzahl privateKey = XB + incrementVal;
	
	pair<pair<Zp,Zp>, uberzahl> ciphertext = ec.encrypt(publicKey, privateKey, plaintext0,plaintext1);
	cout<<"Encrypted ciphertext is: ("<<ciphertext.first.first<<", "<<ciphertext.first.second<<", "<<ciphertext.second<<")\n";
	pair<Zp,Zp> plaintext_out = ec.decrypt(ciphertext);
	
	cout << "Original plaintext is: (" << plaintext0 << ", " << plaintext1 << ")\n";
	cout << "Decrypted plaintext: (" << plaintext_out.first << ", " << plaintext_out.second << ")\n";


	if(plaintext0 == plaintext_out.first && plaintext1 == plaintext_out.second)
		cout << "Correct!" << endl;
	else
		cout << "Plaintext different from original plaintext." << endl;
	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	cout << "\nTIME :" << time_spent << "seconds" << endl;
}

int main(void) {

  //run with large parts of message.
  {
    uberzahl part1 = "5192194303766841028825845";
    uberzahl part2 = "5325995014746560938717301";
    run(part1, part2, 3);
  }

  //run with small message part one, large part two.
  {
    uberzahl part1 = "5";
    uberzahl part2 = "5325995014746560938717301";
    run(part1, part2, 34);
  }

  //run with large message part one, small part two.
  {
    uberzahl part1 = "8324573705019449783825930518";
    uberzahl part2 = "1";
    run(part1, part2, 5);
  }

  //run with small parts of message.
  {
    uberzahl part1 = "3";
    uberzahl part2 = "2";
    run(part1, part2, 75);
  }

  //run with negative part 1.
  {
    uberzahl part1 = "-45364847";
    uberzahl part2 = "99879283";
    run(part1, part2, 9);
  }

  //run with negative part 2.
  {
    uberzahl part1 = "1897490";
    uberzahl part2 = "-94874373";
    run(part1, part2, 2);
  }

  //both parts negative.
  {
    uberzahl part1 = "-8372526374";
    uberzahl part2 = "-2439723";
    run(part1, part2, 9);
  }

  //run with negative offset.
  {
    uberzahl part1 = "45364847";
    uberzahl part2 = "99879283";
    run(part1, part2, -9);
  }

  // Addition/subtraction.
  {
    Zp x1 = 49;
    Zp x2 = 50;
    Zp y1 = 234532910;
    Zp y2 = 3847762;
    
    ECpoint point1(x1, y1);
    ECpoint point2(point1 + (-point1));
    cout << point1 << endl;
    cout << point1 + (-point2) << endl;
    cout << point1 - point2 << endl;
  }

  // Same points.
  {
    ECpoint point1(38470, 0);
    ECpoint point2(38470, 0);
    cout << point1 + point2 << endl;
  }

  // Repeat sum.
  {
    ECpoint point1(true);
    ECpoint point2(847,4943);
    uberzahl power1("0");
    uberzahl power2("-4");

    cout << point1.repeatSum(point1, power1) << endl;
    cout << point1.repeatSum(point2, power2) << endl;
    cout << point1.repeatSum(point2, power1) << endl;
  }
  
  return 0;
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
