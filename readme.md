# User Authentication System

This is a command-line user authentication system written in C++ that allows users to register and login with a username and password. User passwords are stored as a salted and hashed value in a file named `users.txt`. 

## Prerequisites

This program requires the following libraries to be installed:

- OpenSSL: Provides cryptographic functionality for the salt and hash functions


## Usage


1. Register: Allows users to register a new account by entering a username and password.
2. Login: Allows users to login to an existing account by entering a username and password.
3. Exit: Exits the program.

When registering a new account, the program generates a random salt value, which is used along with the password to compute a hash value that is stored in the `users.txt` file.

When logging in, the program checks if the user exists and compares the computed hash value with the stored hash value in the `users.txt` file. If the password is incorrect, the user is given a limited number of attempts to try again. If the number of attempts exceeds the maximum number of attempts specified in `MAX_ATTEMPTS` constant, the user is locked out of the system for a specified amount of time specified in `LOCK_TIME` constant.

## Constants

There are several constants defined at the beginning of the `main()` function that can be customized:

- `MAX_ATTEMPTS`: Specifies the maximum number of attempts allowed for a user to enter the correct password before they are locked out of the system.
- `LOCK_TIME`: Specifies the amount of time, in seconds, a user is locked out of the system if they exceed the maximum number of attempts.
- `SALT_SIZE`: Specifies the size of the salt value in bytes.
- `HASH_SIZE`: Specifies the size of the hash value in bytes.

## Functions

There are several functions in the program that perform various tasks:

- `generateSalt()`: Generates a random salt value.
- `generateHash(string password, string salt)`: Computes the hash value of a password and salt value.
- `isUserLocked(string username)`: Checks if a user is locked out of the system.
- `registerUser()`: Registers a new user.
- `loginUser()`: Logs in an existing user.

