/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- *
*
 * Copyright (c) 2005 University of Dortmund.
 * All rights reserved.                                            
 *                                                                
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation, advertising
 * materials, and other materials related to such distribution and use
 * acknowledge that the software was developed by the University of
 * Dortmund, Mobile Computing Systems Group.  The name of the
 * University may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * 
 
* Project Reliable Data Transport over Multihop Wireless Networks
 * Principal Investigator: Christoph Lindemann
 * Ph.D. Student: Sherif M. ElRakabawy
 *
 * The development of TCP with Adaptive Pacing, TCP-AP, and its ns-2 
 * simulation software has been funded in part by the German Research 
 * Council (DFG). A detailed description of TCP-AP and a comparative 
 * performance study is given in: 
 * S. ElRakabawy, A. Klemm, and C. Lindemann, TCP with Adaptive
 * Pacing for Multihop Wireless Networks, Proc. ACM
 * International Symposium on Mobile Ad Hoc Networking and
 * Computing (MobiHoc 2005), Urbana-Champaign, IL, USA, May 2005.
 *
 * This implementation of TCP-AP is based on TCP NewReno.
 *
 * Author: Sherif M. ElRakabawy
 * <sme@mobicom.cs.uni-dortmund.de>
 * September 2005	
 */
#ifndef TCP_TCPAP_H
#define TCP_TCPAP_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "tcp.h"
#include "flags.h"
#include "math.h"
#include "random.h"

#define max(a,b)        a > b ? a : b
#define min(a,b)        a < b ? a : b

/* Set maximum n_hop_delay_ samples history size 
 * NOTE: this value should always be larger than history_.
 */
#define MAXHISTORY	200

/* Set maximum number of packets waiting to be transmitted
 *  NOTE: this value should always be larger than window_ (wnd_ in tcp.cc).
 */ 
#define MAXPKTS2SEND	200

class APTcpAgent;

/* Pacing timer for rate-based transmission */
class PaceTimer : public TimerHandler {
public: 
	PaceTimer(APTcpAgent *a) : a_(a) { }
protected:
	virtual void expire(Event *e);
	APTcpAgent *a_;
};

class APTcpAgent : public TcpAgent {
friend class PaceTimer;
public:
	APTcpAgent();
	virtual void recv(Packet *pkt, Handler *);
	virtual void timeout(int tno);
	virtual void output(int seqno, int reason = 0);
	virtual int command(int argc, const char* const* argv);

protected:
	virtual void pace_timeout();		/* Called after the pace timer expires */
	virtual void set_pace_timer();		/* Reschedule the pace timer */
	virtual void calc_variation();		/* Calculate variation of the n_hop_delay_ samples 
						   (equivalent to the variation of the RTT samples 
						   since n_hop_delay_ is simply a fraction of RTT) */
	
	PaceTimer pace_timer_;			/* Pacing timer for rate-based transmission */
	
	int n_factor_;				/* Spatial reuse constraint factor which mainly
						   depends on ratio between transmission range 
						   and interference range (default is 4 for 250m 
						   transmission range and 550m interference/cs ranges) */
	int ispaced_;
	int initial_pace_;
	
	int emptyCount;
	int notEmptyCount;
	int intoOutputCount;
	int maxBuffSize;
	
	int samplecount_;
	int history_;				/* n_hop_delay_ samples history size */
	int pkts_to_send_;			/* Number of packets waiting to be transmitted */
	int seqno_[MAXPKTS2SEND];		/* Sequence numbers of packets waiting to be transmitted */
	double delaybound_;			/* An upper bound for the n_hop_delay_ samples */
	double rate_interval_;			/* time between successive packet transmissions */
	double n_hop_delay_;			/* How much to delay the transmission to avoid hidden 
						   terminal induced collisions */
	double avg_n_hop_delay_;
	double avg_queuing_delay_;
	double alpha_;				/* smoothing factor for avg_n_hop_delay_ */
	double gamma_;				/* smoothing factor for avg_queuing_delay_ */
	double samples[MAXHISTORY];		/* n_hop_delay_ samples */	
	double coeff_var_;			/* coefficient of variation of n_hop_delay_ samples */
	double adev_;				/* mean absolute deviation n_hop_delay_ samples */
	double ll_bandwidth_;			/* link layer bandwidth (in bits/s) */
};

#endif