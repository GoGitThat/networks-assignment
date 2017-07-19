/**********************************************************************
* file:  sr_router.c
* date:  Mon Feb 18 12:50:42 PST 2002
* Contact: casado@stanford.edu
*
* Description:
*
* This file contains all the functions that interact directly
* with the routing table, as well as the main entry method
* for routing.
*
**********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"


/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

  /* TODO */
  /* We need to clear the ARP cache at in this init maybe? This thought based on piazza post*/

} /* -- sr_init -- */

/*---------------------------------------------------------------------
* Method: sr_handlepacket(uint8_t* p,char* interface)
* Scope:  Global
*
* This method is called each time the router receives a packet on the
* interface.  The packet buffer, the packet length and the receiving
* interface are passed in as parameters. The packet is complete with
* ethernet headers.
*
* Note: Both the packet buffer and the character's memory are handled
* by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
* packet instead if you intend to keep it around beyond the scope of
* the method call.
*
*---------------------------------------------------------------------*/


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /*printf("*** -> Received packet of length %d \n",len);*/
  int  minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "ethernet header is not the right length\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);

  if(ethertype_ip == ethtype){
  	/*printf("we got an ip packet\n");*/
  	minlength += sizeof(sr_ip_hdr_t);
  	if(len < minlength){
  		fprintf(stderr,"ip header is not the right lntgh\n");
  		return;
  	}

  	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));

    /*printf("checking ip sum\n");*/
  	uint32_t ip_sum = iphdr->ip_sum;
  	iphdr->ip_sum = 0;
  	uint32_t ip_cksum = cksum(iphdr,iphdr->ip_hl*IP_HEADER_WORD_LENGTH);
  	if(ip_cksum!=ip_sum){
  		fprintf(stderr,"checksum is wrong\n");
  		return;
  	}
  	iphdr->ip_sum = ip_cksum;
  	/*printf("	check sum matches\n");*/
    if (sr->nat_set == 1) {
      if (nat_packet_handler(sr, packet, len, interface) == -1) {
        return;
      }
    }
  	struct sr_if *destination_interface = has_matching_interface(sr,iphdr->ip_dst);
  	if(destination_interface){
  		/*printf("its our interface,now checking type of ip\n");*/
  		if(iphdr->ip_p==1){
  			/*printf("it's an ICMP type\n");*/
  			sr_icmp_hdr_t *icmp_hdr =(sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
  			if(icmp_hdr->icmp_type!=8||icmp_hdr->icmp_code!=0){
  				printf("a type of icmp we dont support\n");
  				return;
  			}
  			uint32_t icmp_cksum = icmp_hdr->icmp_sum;
  			icmp_hdr->icmp_sum = 0;
  			if(icmp_cksum!=cksum((uint8_t*)icmp_hdr,ntohs(iphdr->ip_len)-sizeof(sr_ip_hdr_t))){
  				fprintf(stderr,"icmp checksum fails\n");
  				return;
  			}
  			icmp_echo(sr,iphdr);
  		}else{
  			icmp_unreachable(sr,iphdr,3);
  		}
  	}else{
  		/*printf("its not ours, forward it\n");*/
  		if(iphdr->ip_ttl==1){
  			/*printf("ip packet ttl will be 0, send time to live exceeded\n");*/
  			icmp_time_exceeded(sr,iphdr);
  			return;
  		}
  		iphdr->ip_ttl = iphdr->ip_ttl-1;
	  	iphdr->ip_sum = 0;
	  	iphdr->ip_sum = cksum(iphdr,iphdr->ip_hl*4);
		struct sr_rt *routing_tbl_ent = longest_match_prefix(iphdr->ip_dst,sr->routing_table);
		if(!routing_tbl_ent){
			/*printf("cant find a match in the routing table, send destination net unreachable\n");*/
			icmp_unreachable(sr,iphdr,0);
		}else{
			struct sr_if* interface = sr_get_interface(sr,routing_tbl_ent->interface);
			cache_or_send(sr,packet,len,routing_tbl_ent->gw.s_addr,interface);
  		}
  	}
  }else if(ethertype_arp == ethtype){
  	/*printf("packet type is an arp\n");*/
  	minlength += sizeof(sr_arp_hdr_t);
   	if (len < minlength)
		fprintf(stderr, "arp header is not the right length\n");
    else{
    	sr_arp_hdr_t *arphdr = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));


    		   	if(ntohs(arphdr->ar_op)==arp_op_request){
    		   		uint32_t _ip = arphdr->ar_tip;

    		   		struct sr_if *interfface = has_matching_interface(sr,_ip);
    		   		/*printf("we got an arp REQUEST\n");*/
    		   		if(interfface){
    		   			/*printf("found the interfface, sending arp reply through said interfface\n");*/

    		   			new_arp_reply(sr,interfface,arphdr->ar_sha,arphdr->ar_sip);
                /*we have to cache our arp reply as well, even though we sent it, and send the waiting
                packets we had waiting on the arp request,now that we know where it is*/
                struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,arphdr->ar_sha,arphdr->ar_sip);
                if(req){
                    /*printf("going to send the packets that were waiting on the arp reply we just sent\n");*/
                    struct sr_packet *pkts = req->packets;
                    struct sr_if* interfaace= 0;
                    while(pkts){
                      interfaace = sr_get_interface(sr,pkts->iface);
                      cache_or_send(sr,pkts->buf,pkts->len,req->ip,interfaace);
                      pkts = pkts->next;
                    }
                    sr_arpreq_destroy(&sr->cache,req);
                    /*printf("all packets sent\n");*/

                  }
    		   		}
    		   	}else if(ntohs(arphdr->ar_op)==arp_op_reply){
    		        /*printf("got an arp reply\n");*/
    		   		struct sr_if *interfface = has_matching_interface(sr,arphdr->ar_tip);
    		   		if(interfface&&
    		   		!strncmp((const char*)interfface->addr,(const char*)arphdr->ar_tha,ETHER_ADDR_LEN)){
    		   		struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,arphdr->ar_sha,arphdr->ar_sip);
    	   			if(req){
    		   				/*printf("going to send the packets that were waiting on the arp reply we recieved\n");*/

    		   				struct sr_packet *pkts = req->packets;
    		   				struct sr_if* interfaace= 0;
    		   				while(pkts){
    		   					interfaace = sr_get_interface(sr,pkts->iface);
    		   					cache_or_send(sr,pkts->buf,pkts->len,req->ip,interfaace);
    		   					pkts = pkts->next;
    		   				}
    		   				sr_arpreq_destroy(&sr->cache,req);
    		   				/*printf("all packets sent\n");*/

    		   			}
    		   		}


    	}
  	}
  }else{
  	/*printf("pkt is not arp or ip \n");*/
  }

  /* fill in code here */

}/* end sr_ForwardPacket */

void icmp_unreachable(struct sr_instance* sr,sr_ip_hdr_t* in_ip_hdr,uint8_t code){
  if(code==0){
    /*printf("Destination net unreachable\n");*/
  }
  if(code==1){
    /*printf("Destination host unreachable\n");*/
  }
	else{
    /*printf("Destination port unreachable\n");*/
  }
	/*get len of a typical icmp reply packet*/
	unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
	/*get space for that packet*/
	uint8_t* new_pkt = (uint8_t*)malloc(len);

	/*get ethernet header part of the packet*/
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(new_pkt);
	/*set ethernet type to ip packet*/
	eth_hdr->ether_type = htons(ethertype_ip);

	/*set correct dest and source addresses*/
	memset(eth_hdr->ether_shost,0x00,ETHER_ADDR_LEN);
	memset(eth_hdr->ether_dhost,0x00,ETHER_ADDR_LEN);

	/*get the ip header part of the new packet and set its parameters*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(new_pkt+sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = in_ip_hdr->ip_tos;
	ip_hdr->ip_len = htons(len-sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_id = in_ip_hdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = in_ip_hdr->ip_src;

	/*check if a routing table entry exists for for the ip dest*/
	struct sr_rt *routing_tbl_ent = longest_match_prefix(ip_hdr->ip_dst,sr->routing_table);

	/*if it doesnt exist we cant reach the ip address*/
	if(!routing_tbl_ent){
		fprintf(stderr,"cant find routing table entry in routing table\n");
		free(new_pkt);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,routing_tbl_ent->interface);

	if(code==3){
		ip_hdr->ip_src = in_ip_hdr->ip_dst;
	}else{
		ip_hdr->ip_src = interface->ip;
	}

	ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr,sizeof(sr_ip_hdr_t));

	/*get icmp header portion of the new packet and set the parameters*/
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_hdr+sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 3;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data,(uint8_t*)in_ip_hdr,ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum  = cksum((uint8_t*)icmp_hdr,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));

	/*cache or send it*/
	cache_or_send(sr,new_pkt,len,routing_tbl_ent->gw.s_addr,interface);
	free(new_pkt);
}

void icmp_time_exceeded(struct sr_instance* sr,sr_ip_hdr_t* in_ip_hdr){
	/*printf("sending icmp time exceeded message\n");*/
	/*get len of a typical icmp ip packet*/
	unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t);
	/*get space for the packet*/
	uint8_t* new_pkt = (uint8_t*)malloc(len);

	/*get ethernet header of the new packet and set its parameters*/
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(new_pkt);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,ETHER_ADDR_LEN);
	memset(eth_hdr->ether_dhost,0x00,ETHER_ADDR_LEN);

	/*get ip header of the new packet and set its parameters*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(new_pkt+sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = in_ip_hdr->ip_tos;
	ip_hdr->ip_len = htons(len-sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_id = in_ip_hdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = in_ip_hdr->ip_src;

	/*check if routing table entry exists, else we dont kow how to get there*/
	struct sr_rt *routing_tbl_ent = longest_match_prefix(ip_hdr->ip_dst,sr->routing_table);
	if(!routing_tbl_ent){
		fprintf(stderr,"cant find routing table entry in routing table\n");
		free(new_pkt);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,routing_tbl_ent->interface);

	ip_hdr->ip_src = interface->ip;
	ip_hdr->ip_sum = cksum(new_pkt+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));

	/*get icmp header portion of the new packet and set parameters*/
	sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t*)(new_pkt+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 11;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data,(uint8_t*)in_ip_hdr,ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum  = cksum((uint8_t*)icmp_hdr,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));

	/*cache or send the packet*/
	cache_or_send(sr,new_pkt,len,routing_tbl_ent->gw.s_addr,interface);
	free(new_pkt);
}

void icmp_echo(struct sr_instance* sr,sr_ip_hdr_t* in_ip_hdr){
	/*printf("sending echo_reply\n");*/

	/*get lenght of the ip packet we received*/
	uint16_t in_ippkt_len = ntohs(in_ip_hdr->ip_len);

	/*set len to ethernet header and size of ip packet received*/
	unsigned int len = sizeof(sr_ethernet_hdr_t)+in_ippkt_len;

	/*set space for enw icmp echo reply*/
	uint8_t* new_pkt = (uint8_t*)malloc(len);

	/*get ethernet header of the new outgoing packet and set its parameters*/
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(new_pkt);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,ETHER_ADDR_LEN);
	memset(eth_hdr->ether_dhost,0x00,ETHER_ADDR_LEN);

	/*get ip header portion of the new packet and set its parameters*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(new_pkt+sizeof(sr_ethernet_hdr_t));
	memcpy(ip_hdr,in_ip_hdr,in_ippkt_len);
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = in_ip_hdr->ip_src;
	ip_hdr->ip_src = in_ip_hdr->ip_dst;
	ip_hdr->ip_sum = cksum(new_pkt+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));

	/*check if routing table entry exists, else we dont know where to send it*/
	struct sr_rt *routing_tbl_ent = longest_match_prefix(ip_hdr->ip_dst,sr->routing_table);
	if(!routing_tbl_ent){
		fprintf(stderr,"cant find routing table entry in routing table\n");
		free(new_pkt);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,routing_tbl_ent->interface);



	/*get icmp header portion of the new packet and set its parameters*/
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(new_pkt+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 0;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum  = 0;
	icmp_hdr->icmp_sum  = cksum((uint8_t*)icmp_hdr,in_ippkt_len-sizeof(sr_ip_hdr_t));

	/*cache or send the packet*/
	cache_or_send(sr,new_pkt,len,routing_tbl_ent->gw.s_addr,interface);
	free(new_pkt);


}

struct sr_rt *longest_match_prefix(uint32_t dest_ip,struct sr_rt *routing_table_entry){
  /*entry that will point to the longest match*/
  struct sr_rt* longest_match = 0;
  /*longest matching mask holding variable*/
	uint32_t longest = 0;
  /*mask variable to and addresses with and compare if they match, then check mask vs longest*/
  uint32_t mask;
	struct sr_rt* routing_table_iter = routing_table_entry;
  /*while entries exist, continue checking*/
	while(routing_table_iter){
    /*get mask*/
		mask = routing_table_iter->mask.s_addr;
    /*check if addresses match then check if mask is longer than the longest we've found so far*/
		if((mask&routing_table_iter->dest.s_addr)==(mask&dest_ip)){
		   	if(!longest_match||(mask>longest)){
		   		longest_match = routing_table_iter;
		   		longest = mask;
		   	}
		}
		routing_table_iter = routing_table_iter->next;
	}
	return longest_match;
}

void cache_or_send(struct sr_instance* sr,uint8_t* packet,unsigned int len,uint32_t tip,struct sr_if* interface){

	/*check if the packet needs to be cached or sent*/
	struct sr_arpentry* arp = sr_arpcache_lookup(&sr->cache,tip);
	if(!arp){
		/*if there is no arp entry,cache the packet*/
		/*printf("arp entry doesnt exist, so cache packet");*/
		sr_arpcache_queuereq(&sr->cache,tip,packet,len,interface->name);
	}else{
		/*get ether part of the packet and set it to the arp cache entry mac addr*/
		/*set source addr to interface addr it is leaving out of and send packet*/
		sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(packet);
		memcpy(eth_hdr->ether_dhost,arp->mac,ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_shost,interface->addr,ETHER_ADDR_LEN);
		sr_send_packet(sr,packet,len,interface->name);
		free(arp);
	}
}

void new_arp_reply(struct sr_instance* sr,struct sr_if* interface,const unsigned char* tha,uint32_t tip){
	/*	get size of a arp reply */
	unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);

	/* request the previous total size */
	uint8_t *packet = (uint8_t*)malloc(len);
	/*printf("sending a arp reply\n");*/

	/*get ethernet header part of the packet*/
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);

	/*set correct host and destination address*/
	memcpy(eth_hdr->ether_dhost,tha,6);
	memcpy(eth_hdr->ether_shost,interface->addr,6);

	/*set ethernet type to arp*/
	eth_hdr->ether_type = htons(ethertype_arp);
	/*get arp header part of the packet*/
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));

	/*set arp header parameters*/
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_hln = 0x06;
	arp_hdr->ar_pln = 0x04;
	/*set arp header type to arp reply*/
	arp_hdr->ar_op = htons(arp_op_reply);
	/*copy in arp header source address*/
	memcpy(arp_hdr->ar_sha,interface->addr,6);
	arp_hdr->ar_sip = interface->ip;
	/*copy in arp header target address*/
	memcpy(arp_hdr->ar_tha,tha,6);
	arp_hdr->ar_tip = tip;

	/*send the packet*/
	sr_send_packet(sr,packet,len,interface->name);
	free(packet);
}
