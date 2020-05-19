//Filename: mapping.c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

//nfho is a nf_hook_ops struct. This struct stores all the
//required information to register a Netfilter hook.
static struct nf_hook_ops nfho;

//hook_func is our Netfilter function that will be called at the pre-routing
//hook. This hook merely logs that Netfilter received a packet and tells
//Netfilter to continue processing that packet.
static unsigned int hook_func(void *priv, struct sk_buff *skb, 
			const struct nf_hook_state *state) {

        struct iphdr *iph;
	struct tcphdr *tcph;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		printk(KERN_INFO "Packet leaving PRE_ROUTING");
		//printk(KERN_INFO "Output source ip: %pI4\n", &iph->saddr);
	        //printk(KERN_INFO "Output source port: %d\n", ntohs(tcph->source));
		printk(KERN_INFO "Output dest ip: %pI4\n", &iph->daddr);
		printk(KERN_INFO "Output dest port: %d\n", ntohs(tcph->dest));
		printk(KERN_INFO "Memory address: %p\n", skb);
		struct net *net;
		struct net_device *dev;
		for_each_net(net) {
			dev = ip_dev_find(net, iph->daddr);
			if (dev) {
				printk(KERN_INFO "Network namespace for ip %pI4 is %u\n", &iph->daddr, net->ns.inum);
			}
		}
		//printk(KERN_INFO "Network namepsace inum of the corresponding socket: %u\n", read_pnet(&skb->sk->sk_net)->ns.inum);
	}
	
        return NF_ACCEPT; //NF_ACCEPT tells the hook to continue processing the packet.

}

//initialize will setup our Netfilter hook when our kernel
//module is loaded.
static int __init initialize(void) {
       // nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
        nfho.hook     = (nf_hookfn*)hook_func; //Points to our hook function.
        nfho.hooknum  = NF_INET_PRE_ROUTING; //Our function will run at Netfilter's pre-routing hook.
        nfho.pf       = PF_INET; //pf = protocol family. We are only interested in IPv4 traffic.
        nfho.priority = NF_IP_PRI_LAST; //Tells Netfilter this hook should be ran "last" (there is of-course, more to this when other hooks have this priority)
        nf_register_net_hook(&init_net, &nfho); //We now register our hook function.
        return 0;
}

static void __exit cleanup(void) {
        nf_unregister_net_hook(&init_net, &nfho); //unregister our hook
}

module_init(initialize);
module_exit(cleanup);
