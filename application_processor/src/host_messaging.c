/**
 * @file host_messaging.c
 * @author Frederich Stine
 * @brief eCTF Host Messaging Implementation 
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "host_messaging.h"

// Print a message through USB UART and then receive a line over USB UART
void recv_input(const char *msg, char *buf) {
    fflush(0);
    print_ack();
    fgets(buf, HOST_MESSAGE_MAX_LENGTH, stdin);
    for (int i = 0; i < HOST_MESSAGE_MAX_LENGTH; ++i) {
        if (buf[i] == '\n') {
            buf[i] = '\0';
            break;
        }
    }
    puts("");
}
