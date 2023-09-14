#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>

const int N = 4;

char* addrs[4] = {
   "10.9.0.5",
   "192.168.60.5",
   "192.168.60.6",
   "192.168.60.7"
};

struct host {
   __u32 addr;
   __u8 pingSeen;
   __u8 synSeen;
};

static struct host hList[4];

static struct nf_hook_ops hook1; 


unsigned int block(void *priv, struct sk_buff *skb,
const struct nf_hook_state *state){
   struct iphdr * iph;
   struct icmphdr* icmph;
   struct tcphdr *tcph;
   int i = 0;

   if(!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);

   

   if(iph->protocol == IPPROTO_ICMP){
      icmph = icmp_hdr(skb);
      if(icmph ->type == ICMP_ECHO){
         for(i = 0; i < N; ++i){
            if(hList[i].addr == iph->saddr)
               hList[i].pingSeen = 1;
         }
      }
   }
   else if(iph->protocol == IPPROTO_TCP){
      tcph = tcp_hdr(skb);
      if(tcph->syn == 1){
         for(i = 0; i < N; ++i){
            if(hList[i].addr == iph->saddr){
               hList[i].synSeen = 1;
            }
         }
      }
   }

   for(i = 0; i < N; ++i){
      if(hList[i].addr == iph->saddr && hList[i].pingSeen && hList[i].synSeen ){
         return NF_DROP;
      }
   }

   return NF_ACCEPT;
}


int registerFilter(void) {
   u32 ipaddr;
   int i = 0;
   printk(KERN_INFO "Registering filters.\n");


   for(i = 0; i < 4; ++i){
      in4_pton(addrs[i], -1, (u8 *)&ipaddr, '\0', NULL);
      hList[i].addr = ipaddr;
      hList[i].pingSeen = 0;
      hList[i].synSeen = 0;

   }


   hook1.hook = block;
   hook1.hooknum = NF_INET_LOCAL_IN;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;



   nf_register_net_hook(&init_net, &hook1);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
}

module_init(registerFilter);
module_exit(removeFilter);
MODULE_LICENSE("GPL");
