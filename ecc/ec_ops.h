#ifndef ZP_H
#define ZP_H

#include <iostream>
#include <utility>
#include "uberzahl.h"
using namespace std;


/*
 * Parameters for EC and transform into constants
 */

#define PRIME_STR "115792089237316195423570985008687907853269984665640564039457584007913129639747"
#define ORDER_STR "115792089237316195423570985008687907853233080465625507841270369819257950283813"
#define A_STR  "-3"
#define B_STR  "25581"  //in hex
#define GX_STR "004F734B 6790D3E5 247FE3DD B4D61F50 24BA2AC0 4BBC1182 3A5D9895 1DC8B48B"
#define GY_STR "10406987 8EEB9C02 D4972630 BF469384 7658942D 8784174F 7C2281E3 F4A8FCC4"
#define MESSAGE0_STR "102501952645538804965012053167150917101618713464079480886877504892990170212995"
#define MESSAGE1_STR "78269492218290584456200150978164075757011280592962175766832158488911648515458"
#define XA_STR      "34561875026648536864764782987389742234992315461526976004626546308686166324417" //private Key of receiver
#define XB_STR      "7864444799928188707972212131590304337952418237266735010547675839370292882522" //private key of sender



const uberzahl PRIME(PRIME_STR);
const uberzahl ORDER(ORDER_STR);
const uberzahl A(A_STR);
const uberzahl B(B_STR,16);
const uberzahl GX(GX_STR,16);
const uberzahl GY(GY_STR,16);
const uberzahl MESSAGE0(MESSAGE0_STR);
const uberzahl MESSAGE1(MESSAGE1_STR);
const uberzahl XA(XA_STR); //private key of receiver
const uberzahl XB(XB_STR); //private key of sender

/*
 * class Zp: An element in GF(p)
 */
class Zp{

	// Overloading cout
	friend ostream& operator<<(ostream& output, const Zp& a);

	private:
	uberzahl value;
	
	public:
	Zp(){}
	Zp(const uberzahl v){
		value = v;
		if(value >= PRIME || value < "0")
			value = value % PRIME;
	}
	Zp(const int v){
		value = v;
		if(value>=PRIME || value < "0")
			value = value % PRIME;
	}
	uberzahl getValue() const { return value; }

	Zp operator + (const Zp &a) const;
	Zp operator - (const Zp &a) const;
	Zp operator - () const;
	Zp operator * (const Zp &a) const;
	bool operator == (const Zp &a) const;
	Zp inverse() const;
};


/*
 * class ECpoint: A point on an elliptic curve
 */
class ECpoint{

	// Overloading cout
	friend ostream& operator<<(ostream& output, const ECpoint& a);

	public:
	Zp x;
	Zp y;
	bool infinityPoint; //If true, the point is the infinity point

	ECpoint(){
		infinityPoint = false;}
	ECpoint(Zp xx, Zp yy){ x = xx; y =  yy; infinityPoint = false;}
	ECpoint(bool inf){ infinityPoint = inf;}

	ECpoint repeatSum(ECpoint p, uberzahl v) const;
	bool operator == (const ECpoint &a) const;
	ECpoint operator + (const ECpoint &a) const;
	ECpoint operator - (const ECpoint &a) const;
	ECpoint operator - () const; //unary negation
};
ECpoint operator * (const uberzahl &a, const ECpoint &b);


/*
 * class ECsystem: Encryption and decryption functions of ec
 */
class ECsystem{
	private:
		uberzahl privateKey;
		ECpoint publicKey;
		ECpoint G; //Generator G
		Zp power(Zp base, uberzahl pow);
		uberzahl pointCompress(ECpoint e);
		ECpoint pointDecompress(uberzahl compressedPoint);
	public:

		ECsystem(){ G = ECpoint(GX, GY);}
		ECpoint getPublicKey(){ return publicKey;}
		
		pair <ECpoint, uberzahl> generateKeys();

		
		pair <pair<Zp,Zp>,uberzahl> encrypt(ECpoint publicKey, uberzahl privateKey, Zp plaintext0, Zp plaintext1);
		pair <Zp,Zp> decrypt(pair<pair<Zp,Zp>,uberzahl> cm);

};

#endif

