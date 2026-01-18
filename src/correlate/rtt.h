#ifndef TRACEROUTE_CORRELATE_RTT_H
#define TRACEROUTE_CORRELATE_RTT_H

/**
 * Calculates RTT in milliseconds.
 * returns negative value on error (e.g. clock skew)
 */
double calculate_rtt(double send_time, double recv_time);

#endif /* TRACEROUTE_CORRELATE_RTT_H */
