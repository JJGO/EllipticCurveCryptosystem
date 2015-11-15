#ifndef UBERZAHL_H
#define UBERZAHL_H
#include<iostream>
#include<string>
#include<vector>
//#include<gmpxx.h>

#define smallType unsigned int
#define mediumType unsigned long long
#define largeType unsigned long long

class uberzahl {
  public:
    uberzahl ( void );
    ~uberzahl ( void );
    uberzahl ( const char*, int base=10 );
    uberzahl ( int );
    uberzahl ( const uberzahl& );
//    uberzahl( const mpz_class& );
    const uberzahl& operator = ( const uberzahl& );

    friend std::ostream& operator << ( std::ostream&, const uberzahl& );

    // arithmetic - not true pass by references :(
    uberzahl operator + ( const uberzahl& ) const;
    uberzahl operator - ( const uberzahl& ) const;
    uberzahl operator * ( const uberzahl& ) const;
    uberzahl operator / ( const uberzahl& ) const;
    uberzahl operator / ( smallType ) const;
    uberzahl operator % ( const uberzahl& ) const;
    smallType operator % ( smallType ) const;
    uberzahl operator - () const; //unary negation

    // comparators
    bool operator > ( const uberzahl& ) const;
    bool operator < ( const uberzahl& ) const;
    bool operator >= ( const uberzahl& ) const;
    bool operator <= ( const uberzahl& ) const;
    bool operator == ( const uberzahl& ) const;
//    bool operator == ( const mpz_class& ) const;
    bool operator != ( const uberzahl& ) const;

    // bitwize operators
    uberzahl operator | ( const uberzahl& ) const;
    uberzahl operator & ( const uberzahl& ) const;
    uberzahl operator ^ ( const uberzahl& ) const; //xor
    uberzahl operator >> ( smallType ) const;
    uberzahl operator << ( smallType ) const;

    smallType bit ( mediumType ) const; //get the nth least significant bit
    smallType bitLength ( void ) const;

    // uses the rand function - to seed use srand (unsigned int seed);
    uberzahl random ( mediumType );

  private:
    std::string string_value;
    bool positive;
    std::vector<smallType> value_vector;
    void convert_to_numeric ( void );
    std::string convert_to_string ( void ) const;
    void clean_bits ( void );
};

uberzahl random ( const uberzahl&, const uberzahl& );

#endif
