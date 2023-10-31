#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <ratio>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

const int MAX_ATTEMPTS = 3;
const int LOCK_TIME = 10; 
const int SALT_SIZE = 32;
const int HASH_SIZE = 32;

// Function to generate a random salt of size SALT_SIZE
string generateSalt() {
    // Generates a random salt and returns it as a hexadecimal string
    unsigned char salt[SALT_SIZE];
    RAND_bytes(salt, SALT_SIZE);
    ostringstream oss;
    oss << hex << setfill('0');
    for (int i = 0; i < SALT_SIZE; ++i) {
        oss << setw(2) << static_cast<unsigned int>(salt[i]);
    }
    return oss.str();
}

// Function to generate a hash of the given password and salt using SHA-256 algorithm
string generateHash(string password, string salt) {
    // Generates a hash of the password and salt using SHA-256 algorithm and returns it as a hexadecimal string
    unsigned char hash[HASH_SIZE];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, salt.c_str(), salt.size());
    EVP_DigestUpdate(mdctx, password.c_str(), password.size());
    EVP_DigestFinal_ex(mdctx, hash, nullptr);
    EVP_MD_CTX_free(mdctx);

    ostringstream oss;
    oss << hex << setfill('0');
    for (int i = 0; i < HASH_SIZE; ++i) {
        oss << setw(2) << static_cast<unsigned int>(hash[i]);
    }
    return oss.str();
}

// Function to check if the user with the given username is locked
bool isUserLocked(string username) {
    // Checks if the user is locked by looking for a lock file, and returns true if the user is currently locked
    ifstream lock_file(username + ".lock");
    if (lock_file.is_open()) {
        time_t lock_time;
        lock_file >> lock_time;
        lock_file.close();
        time_t now = time(nullptr);
        if (now - lock_time < LOCK_TIME) {
            return true;
        } else {
            remove((username + ".lock").c_str());
        }
    }
    return false;
}

// Function to add a new user and check if the user already exists
void registerUser() {
    // Registers a new user with a username and password, and saves the hash and salt to a file
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;

    // Check if the user already exists
    ifstream file("users.txt");
    string line;
    while (getline(file, line)) {
        istringstream iss(line);
        string existing_username, existing_hash, existing_salt;
        iss >> existing_username >> existing_hash >> existing_salt;
        if (existing_username == username) {
            cout << "User already exists." << endl;
            file.close();
            return;
        }
    }

    // Generate salt and hash password
    string salt = generateSalt();
    string hash = generateHash(password, salt);

    // Save username, hash, and salt to file
    ofstream outfile("users.txt", ios::app);
    outfile << username << " " << hash << " " << salt << endl;
    outfile.close();

    cout << "User registered." << endl;
}

// Function to handle user login
void loginUser() {
    // Logs in a user by checking the entered username and password against the stored hash and salt
    string username, password;
    cout << "Enter username: ";
    cin >> username;

    if (isUserLocked(username)) {
        cout << "User is currently locked out. Try again later." << endl;
        return;
    }

    cout << "Enter password: ";
    cin >> password;

    // Check if user exists and password is correct
    ifstream file("users.txt");
    string line;
    while (getline(file, line)) {
        istringstream iss(line);
        string existing_username, existing_hash, existing_salt;
        iss >> existing_username >> existing_hash >> existing_salt;
        if (existing_username == username) {
            if (generateHash(password, existing_salt) == existing_hash) {
                cout << "Login successful." << endl;
                file.close();
                return;
            } else {
                cout << "Incorrect password." << endl;
                break;
            }
        }
    }
    file.close();
    cout << "User does not exist." << endl;

    // Lock user out if too many failed attempts
    static int attempts = 0;
    if (++attempts >= MAX_ATTEMPTS) {
        ofstream lock_file(username + ".lock");
        lock_file << time(nullptr) << endl;
        lock_file.close();
        cout << "Too many failed attempts. User locked out for " << LOCK_TIME << " seconds." << endl;
        attempts = 0;
    }
}

// Main function to drive the program
int main() {
    // Seed random number generator
    RAND_poll();

    // Initialize OpenSSL
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_MD_CTX_free(mdctx);

    int choice;
    do {
        // Display menu options
        cout << "1. Register" << endl;
        cout << "2. Login" << endl;
        cout << "3. Exit" << endl;
        cout << "Enter choice: ";
        cin >> choice;

        // Switch case to handle user's choice
        switch (choice) {
            case 1:
                registerUser();
                break;
            case 2:
                loginUser();
                break;
            case 3:
                break;
            default:
                cout << "Invalid choice. Try again." << endl;
                break;
        }

    } while (choice != 3);

    return 0;
}
