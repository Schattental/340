//
// Created by Beni on 19/11/2022.
//
#include <iostream>
#include "phc-winner-argon2/include/argon2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <bits/stdc++.h>
#include "UserCred.h"

using namespace std;


#define PWD "password"

string u_name = "Peter";
uint8_t u_salt[SALTLEN]; //salt is 69
string u_hash = "166b5d0c7cccabec38d226550180997b485fbd72edfb706214ed483be3b64343"; //password is login123
//uint8_t hash1[HASHLEN];
//uint8_t hash2[HASHLEN];

//uint8_t salt[SALTLEN];
//memset( salt, 0x00, SALTLEN );

vector <string> UserCred::Get_db(string name) {
    //should request info here
    vector <string> info;
    if(name != u_name){ //check if name exists in db
        throw(LoginException());
    }else{
        //store values found in db to vector string
        // get name, salt, hash
        memset(u_salt, 69, SALTLEN);
        info.push_back(u_name);
        info.push_back(to_string(unsigned(*u_salt)));
        info.push_back(u_hash);
    }
    return info;
}

UserCred::UserCred() {
    password_in = "Guest";
    user_name = "Guest";
}

UserCred::UserCred(string pw_in, string user_n) {
    usr = Get_db(user_n); //store the result of db
    user_name = user_n; // assign user name
    uint8_t *pwd = (uint8_t *)strdup(pw_in.c_str()); //convert input pw for argon
    uint32_t pwdlen = strlen((char *)pwd); // length for argon
    uint8_t usr_salt[SALTLEN];
    memset(usr_salt, stoi(usr[1]), SALTLEN); //reinterpret_cast<uint8_t>(usr_salt)
    HashArgon2i(pwd, pwdlen, usr_salt); // modifying existing hash1 to store hash of input pw
}

string UserCred::HashArgon2i(uint8_t *pwd, uint32_t pwdlen, uint8_t *usr_salt) {
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, usr_salt, SALTLEN, hash1, HASHLEN);
    argon2_context context = {
            hash2,  /* output array, at least HASHLEN in size */
            HASHLEN, /* digest length */
            pwd, /* password array */
            pwdlen, /* password length */
            usr_salt,  /* salt array */
            SALTLEN, /* salt length */
            NULL, 0, /* optional secret data */
            NULL, 0, /* optional associated data */
            t_cost, m_cost, parallelism, parallelism,
            ARGON2_VERSION_13, /* algorithm version */
            NULL, NULL, /* custom memory allocation / deallocation functions */
            /* by default only internal memory is cleared (pwd is not wiped) */
            ARGON2_DEFAULT_FLAGS
    };
    int rc = argon2i_ctx( &context );
    if(ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    char buffer [50];
    string ss;
    free(pwd);
    for( int i=0; i<HASHLEN; ++i ) {
        //printf("%02x", hash1[i]);
        sprintf(buffer,"%02x", hash1[i]);
        ss += buffer;
    }
    password_in = ss;
    //printf( "\n" );
    cout << ss << endl;

    if (memcmp(hash1, hash2, HASHLEN)) {
        for( int i=0; i<HASHLEN; ++i ) {
            printf("%02x", hash2[i]);
        }
        printf("\nfail\n");
    }
    else printf("ok\n");
}

bool UserCred::CheckAccess() {
    //cout << usr[2] << endl;
    if(usr[2] == password_in){
        return true;
    }else{
        return false;
    }
}


int main(void)
{
    //clock_t start, end;

    /* Recording the starting clock tick.*/
    //start = clock();
    string p, n;
    cout << "Name: ";
    cin >> n;
    cout << "\nPassword: ";
    cin >> p;
    cout << endl;

    UserCred u1(p,n);
    if(u1.CheckAccess()){
        cout << "Access granted" << endl;
    }else{
        cout << "Access denied" << endl;
        throw(LoginException());
    }

    //end = clock();

    // Calculating total time taken by the program.
    //double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
    //cout << "Time taken by program is : " << fixed
    //     << time_taken << setprecision(5);
    //cout << " sec " << endl;

}