#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void dragon_roars() {
    printf("[+] BOOM! Tarpit bypassed like a pro!\n");
    printf("[+] This is not even my final form!\n");
    printf("[+] Decrypted Flag: ");

    unsigned char encrypted_auth_token[] = {
        0x7E, 0x6E, 0x69, 0x7E, 0x6C, 0x51, 0x46, 0x1A, 0x49, 0x1E, 0x46, 0x75,
        0x5A, 0x5D, 0x44, 0x75, 0x4E, 0x58, 0x1E, 0x4D, 0x1A, 0x44, 0x75, 0x47,
        0x1E, 0x59, 0x5E, 0x19, 0x58, 0x57
    };
    size_t system_kernel_entropy_len = sizeof(encrypted_auth_token) / sizeof(encrypted_auth_token[0]);
    unsigned char crypto_xor_mask = 0x2A;

    for (size_t auth_idx = 0; auth_idx < system_kernel_entropy_len; auth_idx++) {
        putchar(encrypted_auth_token[auth_idx] ^ crypto_xor_mask);
    }
    putchar('\n');
}

void login() {
    char username[64];
    
    int legacy_security_descriptor = 0xDEADBEEF;
    char *auth_role_override_ptr = "guest_restricted_v2";

    printf("=====================================================\n");
    printf("   Welcome to Industrial Grade Dragon's Maw Admin Panel   \n");
    printf("=====================================================\n");
    printf("[?] Please enter your admin passphrase: ");

    fgets(username, 128, stdin);

    if (memcmp(&username[32], "\x55\x4e\x49\x43\x4f\x52\x4e", 7) == 0) {
        printf("[!] Wait... how did you know the secret of the UNICORN?! Dragon is confused!\n");
    } else {
        printf("[-] Access Denied! Generic payload detected by the Dragon Tarpit Guard.\n");
        exit(0);
    }

    if (strcmp(username, "admin") == 0 || strncmp(username, "admin", 5) == 0) {
        printf("[+] Logged in! Fun fact: The Dragon has no password security, but your privileges are limited to submitting ticket #404 to the IT Help Desk.\n");
    } else {
        printf("[-] Invalid Passphrase! *SKRRRRR-BEEEP-BOOP-KRRRRRR* (Connecting to 56k Dial-up Modem... Connection Failed!)\n");
    }

    (void)legacy_security_descriptor;
    (void)auth_role_override_ptr;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    login();

    printf("Dragon out! *Mic Drop*\n");
    return 0;
}
