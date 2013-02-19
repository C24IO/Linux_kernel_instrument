/* 
 * probes_network_stack.c 
 * Copyright (C) 2013 Chaitanya H. <C@24.IO>
 * Version 1.0: Wed Feb 13 06:23:03 PST 2013
 * 
 * This file is a part of an effort to instrument the network stack of Linux kernel.
 * I am using it to study the Linux TCP/IP stack flow through the Linux kernel.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * 
 * Seed code from: samples/kprobes/kprobe_example.c & samples/kprobes/jprobe_example.c
 * Read more: Documentation/kprobes.txt 
 * Machine: 3.2.0-37-generic
 *
 */

#include<linux/module.h> 
#include<linux/version.h> 
#include<linux/kernel.h> 
#include<linux/init.h> 
#include<linux/kprobes.h> 
#include<net/ip.h> 
 
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Chaitanya H <C@24.IO>");
MODULE_DESCRIPTION("Instrument the network stack of Linux kernel");
MODULE_ALIAS("probe_network_stack");

#define PROBE_FUNC "netif_receive_skb"

//Bringing this back just so that this can compile and I can see things. 

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

//int netif_receive_skb(struct sk_buff *skb)
/* Proxy routine having the same arguments as actual do_fork() routine */
static int netif_receive_skb_handler(struct sk_buff *skb) {

	struct iphdr *my_iph;
    	struct tcphdr *my_tcph;
	u32 S_ip, D_ip, Seq_num, Ack_num;
    	u16 P_id, S_prt, D_prt;

    	my_iph = ip_hdr(skb);
    	my_tcph = tcp_hdr(skb);

	S_prt = my_tcph->source;
    	D_prt = my_tcph->dest;
    	Seq_num = my_tcph->seq;
    	Ack_num = my_tcph->ack_seq;

    	S_ip = my_iph->saddr;
    	D_ip = my_iph->daddr;
    	P_id = my_iph->id;

    	printk("\n\nTuple: "NIPQUAD_FMT,NIPQUAD(S_ip));
    	printk(":%d",S_prt);
    	printk("-"NIPQUAD_FMT,NIPQUAD(D_ip));
    	printk(":%d ",D_prt);

    	printk(" ID - %d Seq - %d Ack - %d\n\n", P_id, Seq_num, Ack_num);

    	//Tuple: SIP:SPORT DIP:DPORT
    	//ID: IP-ID
    	//SEQ: TCP-SEQ:TCP-ACK


        /* Always end with a call to jprobe_return(). */
        jprobe_return();
        return 0;
}

static struct jprobe netif_receive_skb_jprobe = {
        .entry                  = netif_receive_skb_handler,
        .kp = { 
                .symbol_name    = PROBE_FUNC,
        },
};

static struct kprobe kp = {
	.symbol_name = PROBE_FUNC,
}; 

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
        /*printk(KERN_INFO "pre_handler: p->addr = 0x%p, ip = %lx,"
                        " flags = 0x%lx\n",
                p->addr, regs->ip, regs->flags);
*/
        /* A dump_stack() here will give a stack backtrace */

	printk(KERN_INFO "\n======STACK START======\n");
	dump_stack(); //above is proven :-) 
	printk(KERN_INFO "\n======STACK END======\n");

        return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
                                unsigned long flags)
{
        /*printk(KERN_INFO "post_handler: p->addr = 0x%p, flags = 0x%lx\n",
                p->addr, regs->flags);*/
	;
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
        printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
                p->addr, trapnr);
        /* Return 0 because we don't handle the fault. */
        return 0;
}
 
static int __init myinit(void) 
{ 

    int ret;

    printk("module inserted\n "); 

    //my_probe.kp.addr = (kprobe_opcode_t *)0xffffffff81570830; //cat /proc/kallsyms | grep ip_rcv gets you ffffffff8156b770 T ip_rcv

    ret = register_jprobe(&netif_receive_skb_jprobe);
    if (ret < 0) {
    	printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
        return -1;
    }

    printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
               netif_receive_skb_jprobe.kp.addr, netif_receive_skb_jprobe.entry);

    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    ret = register_kprobe(&kp);
    if (ret < 0) {
    	printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
    	return ret;
    }

    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    return 0; 
} 
 
static void __exit myexit(void) 
{ 
    unregister_kprobe(&kp); 
    printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);

    unregister_jprobe(&netif_receive_skb_jprobe);
    printk(KERN_INFO "jprobe at %p unregistered\n", netif_receive_skb_jprobe.kp.addr);

    printk("module removed\n "); 
} 
 
 
module_init(myinit); 
module_exit(myexit); 

