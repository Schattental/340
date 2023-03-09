//
// Created by Beni on 19/11/2022.
//

#ifndef NAVIGATE_USERCRED_H
#define NAVIGATE_USERCRED_H

#include <iostream>
#include <cstdlib>
#include <vector>
#include <cstring>
using namespace std;

#define HASHLEN 32
#define SALTLEN 32

class LoginException: public exception{
public:
    virtual const char* what() const throw(){
        return "\nIncorrect name or password\n";
    }
};

class UserCred{
private:
    vector <string> usr; //requested info from db
    string password_in;
    string user_name;
    uint8_t hash1[HASHLEN]; // hashed input
    uint8_t hash2[HASHLEN];
    uint8_t salt[SALTLEN];
    uint32_t t_cost = 3;            // 3-pass computation
    uint32_t m_cost = (1<<18);      // 64 mebibytes memory usage for 1<<16
    uint32_t parallelism = 8;       // number of threads and lanes
public:
    UserCred();
    UserCred(string pw_in, string user_n);
    vector <string> Get_db(string name); //gets database entry with user_name, pw_db (hashed password) and salt
    string HashArgon2i(uint8_t *pwd, uint32_t pwdlen, uint8_t *usr_salt);
    bool CheckAccess();
};

#endif //NAVIGATE_USERCRED_H
