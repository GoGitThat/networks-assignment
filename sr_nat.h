
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define ACK_BIT 16
#define SYN_BIT 2
#define FIN_BIT 1
#define start_port  1024
#define ID_MIN  1
#define UNSOLICITED_TIMEOUT 6

typedef enum {
  syn_sent,
  syn_received,
  fin_wait1,
  fin_wait2,
  established,
  closed
} con_status;

struct unsolicited_syn_packet {
  uint8_t *packet;
  unsigned int len;
  char* interface;
  sr_ip_hdr_t *ip_header;
  time_t last_updated;
  struct unsolicited_syn_packet *next;
};

struct tcp_connection_status {
  uint32_t sequence_number;
  uint32_t acknoledge_number;
  con_status state;
};


typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint8_t established;
  struct tcp_connection_status src_state;
  struct tcp_connection_status dst_state;
  time_t last_updated;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint32_t src_port;
  uint32_t dst_port;
  uint8_t flags;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  struct sr_instance* sr;
  struct unsolicited_syn_packet* unsolicited_syn_packets;
  uint16_t id;
  uint16_t port;
  unsigned int icmp_timeout_expiry;
  unsigned int tcp_established_timeout;
  unsigned int tcp_transitory_timeout;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


struct sr_tcp_pseudo_hdr
{
  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t length;
} __attribute__ ((packed)) ;
typedef struct sr_tcp_pseudo_hdr tcp_hdr_pseudo_t;

struct sr_tcp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t sequence_number;
  uint32_t acknoledge_number;
  uint8_t offset;
  uint8_t flags;
  uint16_t window;
  uint16_t tcp_sum;
  uint16_t urgent;
} __attribute__ ((packed)) ;
typedef struct sr_tcp_hdr tcp_hdr_t;



int nat_packet_handler(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type, struct sr_nat_connection* conn);

/* Get the mapping associated with given internal (ip, port) pair.
You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, struct sr_nat_connection* conn);

/* Insert a new mapping into the nat's mapping table.
You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, sr_nat_mapping_type type, struct sr_nat_connection* conn);


  #endif
