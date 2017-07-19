#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include "sr_rt.h"
#include "sr_nat.h"
#include "sr_router.h"
#include "sr_utils.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
  /* set the unsolicited_syn_packets to null */
  nat->unsolicited_syn_packets = NULL;
  nat->mappings = NULL;
  /* set the nat identifier to the 1 */
  nat->id = ID_MIN;
  /* set the starting port for the nat(increment for each connection) */
  nat->port = start_port;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  /* get all the mappings */
  struct sr_nat_mapping* mapping = nat->mappings;
  /* while mappings exist */
  while (mapping) {
    /* get the next mapping and the list of connections on the mapping */
    struct sr_nat_mapping *nextm = mapping->next;
    struct sr_nat_connection *conn = mapping->conns;
    /* while the connection exists */
    while (conn) {
      /* get the pointer to the next connection and free the current connection */
      struct sr_nat_connection *nextc = conn->next;
      free(conn);
      conn = nextc;
    }
    /* free the mapping once all the connection have been free'd */
    free(mapping);
    /* get the next mapping */
    mapping = nextm;
  }

  /* get the list of unsolicied syn packets */
  struct unsolicited_syn_packet* pkt = nat->unsolicited_syn_packets;
  /* while packets exist, free get pointer to the next one and free the current one */
  while (pkt) {
    struct unsolicited_syn_packet* nextp = pkt->next;
    free(pkt);
    pkt = nextp;
  }

  /* return */
  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
  pthread_mutexattr_destroy(&(nat->attr));

}


void unsolicited_timeout_handler(struct sr_nat *nat) {
  /* get current time */
  time_t curtime = time(NULL);

  /* iterate over the unsolicited packets */
  struct unsolicited_syn_packet *iterate_list = NULL;
  /* pointer to previous packet (in case we need to remove a packet in the middle) */
  struct unsolicited_syn_packet *prev = NULL;
  /* pointer to the next packet after the current one */
  struct unsolicited_syn_packet *next = NULL;
  /* for each packet not null and next exists */
  for (iterate_list = nat->unsolicited_syn_packets; iterate_list != NULL; iterate_list = iterate_list->next)
  {
    /* if the difference in time is greater unsolicited timeout */
    if (difftime(curtime, iterate_list->last_updated) > UNSOLICITED_TIMEOUT) {
      /* if prev exists, meaning this is not the first packet in the link */
      /* essentially lose pointer to current since its last_updated > timeout time  */
      if (prev) {
        next = iterate_list->next;
        prev->next = next;
      } else {
        next = iterate_list->next;
        nat->unsolicited_syn_packets = next;
      }
      /* send icmp port unreachable packet */
      sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(iterate_list->packet+sizeof(sr_ethernet_hdr_t));
      icmp_unreachable(nat->sr,ip_hdr,3);
    }
    /* set previous to current and current to next */
    prev = iterate_list;
  }
}

/* connection timeout handling */
void connection_timeout_handler(struct sr_nat *nat, struct sr_nat_mapping *mapping) {

  /* get current time */
  time_t curtime = time(NULL);
  /* iterate through all the connections waiting on this mapping */
  struct sr_nat_connection *conn = NULL;
  struct sr_nat_connection *prev = NULL;
  struct sr_nat_connection *next = NULL;
  /* for each  connection  */
  for (conn = mapping->conns; conn != NULL; conn = conn->next) {
    /* if connecion is established, use tcp_established_timeout.
    else connecion is not established, use tcp_transitory_timeout.
    */
    if (((conn->src_state.state == established || conn->dst_state.state == established) &&
    difftime(curtime, mapping->last_updated) > nat->tcp_established_timeout) ||
    (!(conn->src_state.state == established || conn->dst_state.state == established) &&
    difftime(curtime, mapping->last_updated) > nat->tcp_transitory_timeout)) {
      /* if previous exists meaning this isnt the first packet */
      /* essentially lose pointer to current since its last_updated > timeout time  */
      if (prev) {
        next = conn->next;
        prev->next = next;
      } else {
        next = conn->next;
        mapping->conns = next;
      }
      continue;
    }
    prev = conn;
  }
}

/* Periodic Timeout handling */
void *sr_nat_timeout(void *nat_ptr) {
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));
    unsolicited_timeout_handler(nat);
    /* get current time */
    time_t curtime = time(NULL);
    /* get the mappings */
    struct sr_nat_mapping *mapping = NULL;
    struct sr_nat_mapping *prev = NULL;
    struct sr_nat_mapping *next = NULL;
    int del_mapping_flag = 0; /* flag indicates whether to delete current mapping */
    for (mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
      del_mapping_flag = 0;
      /* if the mapping is tcp, loop through all its connections and update them */
      if (mapping->type == nat_mapping_tcp) {
        connection_timeout_handler(nat, mapping);
        /* if the list is null, that means they were all timed out and so this mapping can be deleted */
        if (mapping->conns==NULL) {
          del_mapping_flag = 1;
        }
      }
      /* if the mapping is icmp and the icmp mapping updated is greater than time out, mark for deletion */
      else if (mapping->type == nat_mapping_icmp){
        if (difftime(curtime, mapping->last_updated) > nat->icmp_timeout_expiry) {
          del_mapping_flag = 1;
        }
      }
      /* essentially lose pointer to current (prev points to next,next points to next) since its last_updated > timeout time  */
      if (del_mapping_flag) {
        if (prev) {
          next = mapping->next;
          prev->next = next;
        } else {
          next = mapping->next;
          nat->mappings = next;
        }
        /* free the mapping */
        free(mapping);
        continue;
      }
      /* incrment pointers */
      prev = mapping;
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* calculate TCP checksum*/
uint16_t tcp_cksum(sr_ip_hdr_t *ip_header, tcp_hdr_t *tcp_header, int len)
{
  uint16_t result = 0;
  int tcpLen = len - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t);
  uint8_t *buf = (uint8_t *)malloc(sizeof(tcp_hdr_pseudo_t) + tcpLen);
  tcp_hdr_pseudo_t *ph = (tcp_hdr_pseudo_t *)buf;
  ph->src_ip = ip_header->ip_src;
  ph->dst_ip = ip_header->ip_dst;
  ph->reserved = 0;
  ph->protocol = ip_header->ip_p;
  ph->length = htons(tcpLen);
  memcpy(buf + sizeof(tcp_hdr_pseudo_t), tcp_header, tcpLen);
  result = cksum(buf, sizeof(tcp_hdr_pseudo_t) + tcpLen);
  free(buf);
  return result;
}


void unsolicited_syn_remove(struct sr_nat *nat, uint16_t port) {
  pthread_mutex_lock(&(nat->lock));

  struct unsolicited_syn_packet* iterate_list = NULL;
  struct unsolicited_syn_packet* prev = NULL;
  struct unsolicited_syn_packet* next = NULL;
  for(iterate_list = nat->unsolicited_syn_packets; iterate_list != NULL; iterate_list = iterate_list->next) {
    /* if the tcp header destination port matches port */
    tcp_hdr_t *tcp_header = (tcp_hdr_t *)(iterate_list->ip_header + 1);
    if (tcp_header->dst_port == port) {
      if (prev) {
        next = iterate_list->next;
        prev->next = next;
      } else {
        next = iterate_list->next;
        nat->unsolicited_syn_packets = next;
      }
      continue;
    }
    prev = iterate_list;
  }

  pthread_mutex_unlock(&(nat->lock));
}

/* update mapping tcp connection state with incoming packet */
int connection_update(struct sr_nat *nat, struct sr_nat_mapping* mapping, struct sr_nat_connection *conn) {

  pthread_mutex_lock(&(nat->lock));

  /* get the connections on the mapping */
  struct sr_nat_connection* iterate_list = mapping->conns;
  while(iterate_list) {
    /*  if the destination/source ips and ports match*/
    if (iterate_list->src_ip == conn->src_ip &&
      iterate_list->dst_ip == conn->dst_ip &&
      iterate_list->src_port == conn->src_port &&
      iterate_list->dst_port == conn->dst_port) {

        /*  set time upadted to now*/
        conn->last_updated = time(NULL);
        /* ack packet */
        /* if the sequence number in the connection state is greater than current assign it to current */
        if (conn->src_state.sequence_number > iterate_list->src_state.sequence_number) {
          iterate_list->src_state.sequence_number = conn->src_state.sequence_number;
        }

        /* if the connection has been acknoledge_numberwledged */
        if ((conn->flags & ACK_BIT) == ACK_BIT) {
          /*if the destination has received the syn packet and the source ack take away dest sequence number is 1 */
          /* means source sent syn, dest got it, set dest state to connection established  */
          if(iterate_list->dst_state.state == syn_received &&
            conn->src_state.acknoledge_number - iterate_list->dst_state.sequence_number == 1) {
              iterate_list->dst_state.state = established;
            }
            /* if the current  dest state is waiting on a fin ack and the source ack take away dest seq >1(multiple sent) */
            /* set destination status to fin2 */
            if(iterate_list->dst_state.state == fin_wait1 &&
              conn->src_state.acknoledge_number - iterate_list->dst_state.sequence_number >= 1) {
                iterate_list->dst_state.state = fin_wait2;
              }
              /* if source ack > current source ack, update current source ack */
              if(conn->src_state.acknoledge_number > iterate_list->src_state.acknoledge_number) {
                iterate_list->src_state.acknoledge_number = conn->src_state.acknoledge_number;
              }
            }
            /* the connection is on fin */
            else if ((conn->flags & FIN_BIT) == FIN_BIT) {
              /* if dest is waiting on fin 2, close the connection on destination */
              if(iterate_list->dst_state.state == fin_wait2) {
                iterate_list->dst_state.state = closed;
              } else {
                /* otherwise set the source to fin1 */
                iterate_list->src_state.state = fin_wait1;
              }
            }
            /* if the conn is waiting on SYN sent\ */
            else if ((conn->flags & SYN_BIT) == SYN_BIT) {
              /* if dest state is syn sent, set current dest to syn received */
              if(iterate_list->dst_state.state == syn_sent) {
                iterate_list->dst_state.state = syn_received;
              }
            }
            pthread_mutex_unlock(&(nat->lock));
            return 0;
          }
          iterate_list = iterate_list->next;
        }
        pthread_mutex_unlock(&(nat->lock));
        return -1;
      }

      /* Get the mapping associated with given external port.
      You must free the returned structure if it is not NULL. */
      struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
        uint16_t aux_ext, sr_nat_mapping_type type, struct sr_nat_connection* conn ) {

          pthread_mutex_lock(&(nat->lock));

          /* handle lookup here, malloc and assign to copy */
          struct sr_nat_mapping *copy = NULL;
          /* get the mappings */
          struct sr_nat_mapping *cur_mapping = nat->mappings;
          /* while current exists */
          while (cur_mapping) {
            /* if the port and type match break loop, we found the match */
            if (cur_mapping->aux_ext == aux_ext && cur_mapping->type == type) {
              cur_mapping->last_updated = time(NULL);
              copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
              memcpy(copy, cur_mapping, sizeof(struct sr_nat_mapping));
              break;
            }
            cur_mapping = cur_mapping->next;
          }
          pthread_mutex_unlock(&(nat->lock));
          return copy;
        }

        /* Get the mapping associated with given internal (ip, port) pair.
        You must free the returned structure if it is not NULL. */
        struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
          uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, struct sr_nat_connection* conn) {

            pthread_mutex_lock(&(nat->lock));

            /* handle lookup here, malloc and assign to copy. */
            struct sr_nat_mapping *copy = NULL;
            /* get the mappings */
            struct sr_nat_mapping *cur_mapping = nat->mappings;
            /* while the mapping exists */
            while (cur_mapping) {
              /* if the port,ip and type match */
              if (cur_mapping->aux_int == aux_int && cur_mapping->ip_int == ip_int && cur_mapping->type == type) {
                if (type == nat_mapping_tcp) {
                  /* if there is no matched connection, insert a new connection in the mappings connection list */
                  if (connection_update(nat, cur_mapping, conn) == -1) {
                    struct sr_nat_connection *newConn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
                    memcpy(newConn, conn, sizeof(struct sr_nat_connection));
                    newConn->last_updated = time(NULL);

                    /* if syn is sent, set source syn sent, else set connection to closed */
                    if ((conn->flags & SYN_BIT) == SYN_BIT) {
                      newConn->src_state.sequence_number = conn->src_state.sequence_number;
                      newConn->src_state.state = syn_sent;
                    } else {
                      newConn->src_state.sequence_number = 0;
                      newConn->src_state.state = closed;
                    }
                    /* set the destination state to closed and add it to list of connections */
                    newConn->dst_state.state = closed;
                    newConn->next = cur_mapping->conns;
                    cur_mapping->conns = newConn;
                  }
                }
                /* update mapping time */
                cur_mapping->last_updated = time(NULL);

                /* copy over the mapping */
                copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
                memcpy(copy, cur_mapping, sizeof(struct sr_nat_mapping));

                /* copy int eh connections (possibly wit the new connection added to the list) */
                if (cur_mapping->type == nat_mapping_tcp) {
                  copy->conns = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
                  memcpy(copy->conns, cur_mapping->conns, sizeof(struct sr_nat_connection));
                }
                break;
              }
              cur_mapping = cur_mapping->next;
            }

            pthread_mutex_unlock(&(nat->lock));
            return copy;
          }

          /* Insert a new mapping into the nat's mapping table.
          Actually returns a copy to the new mapping, for thread safety.
          */
          struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
            uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, sr_nat_mapping_type type,
            struct sr_nat_connection* conn) {

              pthread_mutex_lock(&(nat->lock));

              /* handle insert here, create a mapping, and then return a copy of it */
              struct sr_nat_mapping *mapping = NULL;
              /* get mappings*/
              struct sr_nat_mapping *cur_mapping = nat->mappings;
              /* while mappings exist */
              while (cur_mapping) {
                /* if the port and ip and type match malloc mapping and copy it in and return it */
                if (cur_mapping->aux_int == aux_int && cur_mapping->ip_int == ip_int && cur_mapping->type == type) {
                  mapping = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
                  memcpy(mapping, cur_mapping, sizeof(struct sr_nat_mapping));
                  pthread_mutex_unlock(&(nat->lock));
                  return mapping;
                }
                cur_mapping = cur_mapping->next;
              }

              /* mapping doesnt exist, since the function got to this point, create new mapping and set parameters */
              struct sr_nat_mapping* new_mapping = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
              new_mapping->ip_int = ip_int;
              new_mapping->aux_int = aux_int;
              new_mapping->ip_ext = ip_ext;

              /* if its icmp increment icmp idnetifier and increment global nat id */
              /* if it's a icmp packet */
              if (type == nat_mapping_icmp) {
                new_mapping->aux_ext = nat->id;
                nat->id++;
              }
              /* if its tcp */
              else if (type == nat_mapping_tcp) {
                /* set port to current global nat port and increment nat port */
                new_mapping->aux_ext = htons(nat->port);
                nat->port++;

                /* set up a connection list(create empy connection) */
                struct sr_nat_connection* newConn = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
                memcpy(newConn, conn, sizeof(struct sr_nat_connection));
                /* update connection last updated, check flags in case, theyve been updated and set state to 0 */
                newConn->last_updated = time(NULL);
                if ((conn->flags & SYN_BIT) == SYN_BIT) {
                  newConn->src_state.sequence_number = conn->src_state.sequence_number;
                  newConn->src_state.state = syn_sent;
                } else {
                  newConn->src_state.sequence_number = 0;
                  newConn->src_state.state = closed;
                }
                /* set connection state to closed */
                newConn->dst_state.state = closed;
                newConn->next = NULL;
                new_mapping->conns = newConn;
              }

              /* insert mapping into table and update its mapping time */
              new_mapping->last_updated = time(NULL);
              new_mapping->type = type;
              new_mapping->next = nat->mappings;
              nat->mappings = new_mapping;

              /* copy new mapping into mappings and if tis tcp also copy over connections */
              mapping = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
              memcpy(mapping, new_mapping, sizeof(struct sr_nat_mapping));
              if (type == nat_mapping_tcp) {
                mapping->conns = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
                memcpy(mapping->conns, new_mapping->conns, sizeof(struct sr_nat_connection));
              }

              pthread_mutex_unlock(&(nat->lock));
              return mapping;
            }


            int determine_direction(struct sr_rt* rt, char* interface) {
              /* if the packet is destined for eth2, its going out else its coming in */
              if (memcmp(interface, "eth1", 4) == 0 && memcmp(rt->interface, "eth2", 4)==0) {
                /* outbound */
                return 1;
              } else if (memcmp(interface, "eth2", 4) == 0 && memcmp(rt->interface, "eth1", 4)==0) {
                /* inbound */
                return 0;
              } else {
                return -1;
              }
            }

            int nat_icmp(struct sr_instance* sr,
              uint8_t * packet/*len*/,
              unsigned int len,
              char* interface/*len*/) {

                /* get all the headers from the packet */
                sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)packet;
                sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(eth_header+1);
                sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* get the type of the icmp */
                uint8_t type = icmp_header->icmp_type;
                /* packet is echo request or reply, otherwise return -1*/
                if (type == 0 || type==8) {
                  int outbound = 0;
                  struct sr_rt* routing_index = longest_match_prefix(ip_header->ip_dst, sr->routing_table);
                  /* if entry not found */
                  if (routing_index) {
                    outbound = determine_direction(routing_index, interface);
                  } else {
                    return -1;
                  }

                  /* get id of icmp */
                  uint16_t* id = (uint16_t*)(packet+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
                  struct sr_nat_mapping* nat_mapping = NULL;

                  /* if the packet is outbound, search up the nat internally */
                  if (outbound == 1) {
                    /* Outbound packet, look up with src ip and src port*/
                    nat_mapping = sr_nat_lookup_internal(sr->nat, ip_header->ip_src, *id, nat_mapping_icmp, NULL);

                    /* If mapping is still null(doesnt exist in table), insert a new mapping to the mapping table */
                    if (nat_mapping == NULL) {
                      /* get the interface eth2 */
                      struct sr_if* eth2_if = sr_get_interface(sr, "eth2");
                      /* insert the new mapping */
                      nat_mapping = sr_nat_insert_mapping(sr->nat, ip_header->ip_src, *id, eth2_if->ip, nat_mapping_icmp, NULL);
                    }

                    /* get outbound interface */
                    struct sr_if* out_if = sr_get_interface(sr, routing_index->interface);
                    /* copy in the outbound interface of nat as source */
                    memcpy(eth_header->ether_shost, out_if->addr, ETHER_ADDR_LEN);

                    /* set ip source as nat_mapping external ip and the id as external port icmp */
                    ip_header->ip_src = nat_mapping->ip_ext;
                    *id = nat_mapping->aux_ext;

                    /* calcualte ip and icmp checksums */
                    ip_header->ip_sum = 0;
                    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                    icmp_header->icmp_sum = 0;
                    icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                  } else if (outbound == 0) {
                    /* its an inbound packet, look up externally  */
                    nat_mapping = sr_nat_lookup_external(sr->nat, *id, nat_mapping_icmp, NULL);

                    /* mapping was not found, return */
                    if (!nat_mapping) {
                      return -1;
                    }

                    /* set the packet destination as 0 */
                    memset(eth_header->ether_dhost, 0, ETHER_ADDR_LEN);
                    /* set the ip dest as the internal ip address */
                    ip_header->ip_dst = nat_mapping->ip_int;
                    /* set port as interal port */
                    *id = nat_mapping->aux_int;

                    /* update checksums for ip and icmp */
                    ip_header->ip_sum = 0;
                    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                    icmp_header->icmp_sum = 0;
                    icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                  }
                  /* free the mapping */
                  free(nat_mapping);
                }
                return 0;
              }

              int nat_tcp (struct sr_instance* sr,
                uint8_t * packet,
                unsigned int len,
                char* interface) {
                  /* get all the headers */
                  sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)packet;
                  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(eth_header+1);
                  tcp_hdr_t* tcp_header = (tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                  /* figure out whether its outbound or inbound */
                  int outbound = 0;
                  struct sr_rt* routing_index = longest_match_prefix(ip_header->ip_dst,sr->routing_table);
                  /* if entry not found */
                  if (routing_index) {
                    outbound = determine_direction(routing_index, interface);
                  } else {
                    return -1;
                  }
                  /* init map vairable */
                  struct sr_nat_mapping* nat_mapping = NULL;
                  if (outbound ==1) {
                    /*its an outbound packet, search for the mapping using a connection(since loopup takes in a conn arg)*/
                    /* set up connection param using the packet header info */
                    struct sr_nat_connection* conn = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
                    conn->src_ip = ip_header->ip_src;
                    conn->dst_ip = ip_header->ip_dst;
                    conn->src_port = tcp_header->src_port;
                    conn->dst_port = tcp_header->dst_port;
                    conn->flags = tcp_header->flags;
                    conn->src_state.sequence_number = tcp_header->sequence_number;
                    conn->src_state.acknoledge_number = tcp_header->acknoledge_number;

                    nat_mapping = sr_nat_lookup_internal(sr->nat, ip_header->ip_src,
                      tcp_header->src_port, nat_mapping_tcp, conn);

                      /* nat mapping doesnt exist and wasnt found */
                      if (nat_mapping == NULL) {
                        /* get eht interface associated with eth2 and create a mapping for it */
                        struct sr_if* eth2_if = sr_get_interface(sr, "eth2");
                        nat_mapping = sr_nat_insert_mapping(sr->nat, ip_header->ip_src,
                          tcp_header->src_port, eth2_if->ip, nat_mapping_tcp, conn);
                        }
                        /* if syn is set handle the connections on the mapping */
                        if ((tcp_header->flags & SYN_BIT) == SYN_BIT) {
                          unsolicited_syn_remove(sr->nat, nat_mapping->aux_ext);
                        }

                        /* set the headers of the packet using information from the interface */
                        struct sr_if* out_if = sr_get_interface(sr, routing_index->interface);
                        memcpy(eth_header->ether_shost, out_if->addr, ETHER_ADDR_LEN);

                        /* set the source port and ip using the nat's port and ip */
                        ip_header->ip_src = nat_mapping->ip_ext;
                        tcp_header->src_port = nat_mapping->aux_ext;

                        /* update the checksums */
                        ip_header->ip_sum = 0;
                        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                        tcp_header->tcp_sum = 0;
                        tcp_header->tcp_sum = tcp_cksum(ip_header, tcp_header, len);

                      } else if (outbound == 0) {
                        /*its aninbound packet, look up using the dest port */
                        nat_mapping = sr_nat_lookup_external(sr->nat, tcp_header->dst_port, nat_mapping_tcp, NULL);
                        if (nat_mapping ==NULL) {
                          /* the mapping doenst exsit for the interal */
                          if(tcp_header->dst_port < 1024){
                            icmp_unreachable(sr,ip_header,3);
                          }
                          /*handle unsolicited syn, there is no entry, so queue unsolicited syn first*/
                          struct unsolicited_syn_packet* newPkt = (struct unsolicited_syn_packet *)malloc(sizeof(struct unsolicited_syn_packet));
                          newPkt->last_updated = time(NULL);
                          newPkt->packet = packet;
                          newPkt->len = len;
                          newPkt->interface = interface;
                          newPkt->ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));;

                          pthread_mutex_lock(&(sr->nat->lock));
                          newPkt->next = sr->nat->unsolicited_syn_packets;
                          sr->nat->unsolicited_syn_packets = newPkt;
                          pthread_mutex_unlock(&(sr->nat->lock));
                          return -1;
                        }

                        /* set header information of the ip packet source ip/port using nat's attributes */
                        memset(eth_header->ether_dhost, 0, ETHER_ADDR_LEN);
                        ip_header->ip_dst = nat_mapping->ip_int;
                        tcp_header->dst_port = nat_mapping->aux_int;

                        /* recalcualte the checksums */
                        ip_header->ip_sum = 0;
                        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                        tcp_header->tcp_sum = 0;
                        tcp_header->tcp_sum = tcp_cksum(ip_header, tcp_header, len);


                        /* create a new conn and set the attriibutes using the ip header */
                        struct sr_nat_connection* conn = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
                        /* for inbound packet, switch src and dst when generate new connection*/
                        conn->dst_ip = ip_header->ip_src;
                        conn->dst_port = tcp_header->src_port;
                        conn->src_ip = ip_header->ip_dst;
                        conn->src_port = tcp_header->dst_port;
                        conn->flags = tcp_header->flags;
                        conn->src_state.sequence_number = tcp_header->sequence_number;
                        conn->src_state.acknoledge_number = tcp_header->acknoledge_number;
                        /* update connection state */
                        connection_update(sr->nat, nat_mapping, conn);
                      }
                      return 0;
                    }

                    int nat_packet_handler(struct sr_instance* sr,
                      uint8_t * packet,
                      unsigned int len,
                      char* interface) {
                        sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)packet;
                        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(eth_header+1);
                        /* icmp packet */
                        if (ip_header->ip_p == ip_protocol_icmp) {
                          return nat_icmp(sr, packet, len, interface);
                        } else {
                          /* TCP/UDP packet*/
                          return nat_tcp(sr, packet, len, interface);
                        }
                      }
