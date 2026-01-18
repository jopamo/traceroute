#include "rtt.h"

double calculate_rtt(double send_time, double recv_time) {
    if (send_time <= 0 || recv_time <= 0)
        return -1.0;

    double rtt = recv_time - send_time;

    if (rtt < 0) {
        // Clock skew or weirdness.
        // In real world we might clamp to 0 if it's very small negative,
        // but for unit tests we follow the rules.
        return -2.0;
    }

    return rtt * 1000.0;  // Return in ms
}
