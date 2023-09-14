#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

static struct nf_hook_ops hook1, hook2; 

int pingReceived[4]={0, 0, 0, 0};
int tcpReceived[4] = {0, 0, 0, 0};
int blocked[4] = {0, 0, 0, 0};
// order :
// 0: 10.9.0.5
// 1: 192.168.60.5
// 2: 192.168.60.6
// 3: 192.168.60.7

unsigned int blockFunction(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{

    struct iphdr *iph;
    struct icmphdr *icmph;
    struct tcphdr *tcph;

    char my_ip[16] = "10.9.0.1";

    char sip[4][16] = {"10.9.0.5", "192.168.60.5", "192.168.60.6", "192.168.60.7"};
    
    u32 src_ip_addr[4];
    u32 my_ip_addr;

    int i, j;
    for(i=0;i<4;i++)
    {
        in4_pton(sip[i], -1, (u8 *)&src_ip_addr[i], '\0', NULL);
        // printk(KERN_WARNING "*** src ip address", &(src_ip_addr)+i);
    }

    in4_pton(my_ip, -1, (u8 *)&my_ip_addr, '\0', NULL);

    // printk(KERN_WARNING "*** my ip address", &(my_ip_addr));

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);

    
    for(j=0;j<4;j++)
    {
        if(iph->saddr == src_ip_addr[j] && iph->daddr == my_ip_addr)
        {
            if(blocked[j])
                return NF_DROP;
        }
    }

    if (iph->protocol == IPPROTO_ICMP)
    {
        icmph = icmp_hdr(skb);

        if (iph->daddr == my_ip_addr && icmph->type == ICMP_ECHO)
        {

            int j;
            for(j=0;j<4;j++)
            {
                if(iph->saddr == src_ip_addr[j])
                {
                    if(blocked[j])
                    {
                        return NF_DROP;
                    }
                    else 
                    {
                        pingReceived[j] = 1;
                        if(tcpReceived[j])
                        {
                            blocked[j] = 1;
                            printk(KERN_WARNING "***Ping received %pI4 --> %pI4 (ICMP) blocked\n",&(iph->saddr), &(iph->daddr));
                        }
                        
                        
                    }
                    break;

                }
            }
        }
    }


    if (iph->protocol == IPPROTO_TCP)
    {
    	printk(KERN_WARNING "**protocol match");
        tcph = tcp_hdr(skb);

        if (iph->daddr == my_ip_addr && tcph->syn == 1)
        {
		printk(KERN_WARNING "**protocol destination match");
        
            for(j=0;j<4;j++)
            {
                if(iph->saddr == src_ip_addr[j])
                {
                	printk(KERN_WARNING "**protocol source %pI4 match", &(iph->saddr));
        
                    if(blocked[j])
                    {
                        return NF_DROP;
                    }
                    else 
                    {
                        tcpReceived[j] = 1;
                        if(pingReceived[j])
                        {
                            blocked[j] = 1;
                            printk(KERN_WARNING "***TCP received %pI4 --> %pI4 (TCP) blocked\n",&(iph->saddr), &(iph->daddr));
                        }
                        
                    }
                    break;

                }
            }
        }
    }

   return NF_ACCEPT;
}


unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}


int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");
   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);
   
   hook2.hook = blockFunction;
   hook2.hooknum = NF_INET_PRE_ROUTING;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
   
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

