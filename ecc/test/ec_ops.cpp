#include "ec_ops.h"
#include <cstdio>
#include <cstdlib>

//==================== Methods for Zp ====================
Zp Zp::operator+(const Zp &a) const {
	uberzahl result = (this->value + a.value);
	if(result>=PRIME)
		result = result - PRIME;
	return Zp(result);
}

Zp Zp::operator*(const Zp &a) const {
	uberzahl result = (this->value * a.value);
	return Zp(result);
}

Zp Zp::operator-(const Zp &a) const {
	uberzahl result = (this->value - a.value);
	if(result>=PRIME)
		result = result - PRIME;
	if(result<"0")
		result = result + PRIME;
	return Zp(result);
}

Zp Zp::operator-() const {
	uberzahl result = (PRIME - this->value);
	if(result>=PRIME)
		result = result - PRIME;
	return Zp(result);
}

bool Zp::operator==(const Zp &a) const {
	if (this->value == a.value)
		return true;
	return false;
}

ostream& operator<<(ostream& output, const Zp &a){
	output << a.value;
	return output;
}

//================== Methods for ECpoint ==================
bool ECpoint::operator == (const ECpoint &a) const {
	if(this->x == a.x && this->y == a.y)
		return true;
	return false;
}

ECpoint operator * (const uberzahl &a, const ECpoint &b) {
	return b.repeatSum(b, a);
}


ostream& operator << (ostream& output, const ECpoint& a){
	if(a.infinityPoint == true)
		output << "(INF_POINT)";
	else
		output << "(" << a.x << "," << a.y << ")";
	return output;
}

//================= Methods for ECsystem =================

pair <ECpoint, uberzahl> ECsystem::generateKeys(){
	//Generate the private key and public key for the user to whom message is sent
	//Returns only the "P" value of public key and "a" value of private key,
	//as other parameters are globally defined
	
	privateKey = XA;
	publicKey = privateKey*G;
	return pair <ECpoint, uberzahl> (publicKey, privateKey);
}


