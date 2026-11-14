/* Deployment-only read-only rtnetlink dump. Any existing classifier is a
 * conflict: TC_ACT_OK must not bypass another operator's classifier chain. */
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <sys/socket.h>
#include <sys/time.h>
static int deployment_filter_count(int ifindex, int egress)
{
    int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE);
    if(fd<0)return -1;
    struct timeval timeout={.tv_sec=3};
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))){close(fd);return -1;}
    struct {struct nlmsghdr n;struct tcmsg t;} request={
        .n={.nlmsg_len=NLMSG_LENGTH(sizeof(struct tcmsg)),.nlmsg_type=RTM_GETTFILTER,
            .nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP,.nlmsg_seq=1},
        .t={.tcm_family=AF_UNSPEC,.tcm_ifindex=ifindex,
            .tcm_parent=TC_H_MAKE(TC_H_CLSACT,0xfff2)}};
    if(egress)request.t.tcm_parent=TC_H_MAKE(TC_H_CLSACT,0xfff3);
    struct sockaddr_nl address={.nl_family=AF_NETLINK};
    if(sendto(fd,&request,request.n.nlmsg_len,0,(void *)&address,sizeof(address))<0){close(fd);return -1;}
    int count=0;
    for(;;){
        char buffer[65536];struct iovec iov={.iov_base=buffer,.iov_len=sizeof(buffer)};
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
        int received=recvmsg(fd,&msg,0);
        if(received<0&&errno==EINTR)continue;
        if(received<=0 || (msg.msg_flags&MSG_TRUNC)){close(fd);errno=EIO;return -1;}
        unsigned size=received;
        struct nlmsghdr *n;
        for(n=(void *)buffer;NLMSG_OK(n,size);n=NLMSG_NEXT(n,size)){
            if(n->nlmsg_seq!=1 || (n->nlmsg_flags&NLM_F_DUMP_INTR)){close(fd);errno=EINTR;return -1;}
            if(n->nlmsg_type==NLMSG_ERROR){
                const struct nlmsgerr *e=NLMSG_DATA(n);
                errno=n->nlmsg_len>=NLMSG_LENGTH(sizeof(*e))?-e->error:EIO;
                close(fd);if(!errno)errno=EIO;return -1;
            }
            if(n->nlmsg_type==NLMSG_DONE){
                int error=0;
                if(n->nlmsg_len>=NLMSG_LENGTH(sizeof(error)))memcpy(&error,NLMSG_DATA(n),sizeof(error));
                close(fd);if(error){errno=error<0?-error:error;return -1;}return count;
            }
            if(n->nlmsg_type==RTM_NEWTFILTER){
                if(n->nlmsg_len<NLMSG_LENGTH(sizeof(struct tcmsg))){close(fd);errno=EIO;return -1;}
                /* Dumps include a handle-zero classifier-kind header as well
                 * as the actual filters. Only the latter execute packets. */
                const struct tcmsg *filter=NLMSG_DATA(n);
                if(filter->tcm_handle)++count;
            }
        }
        if(size){close(fd);errno=EIO;return -1;}
    }
}

static int deployment_empty_hooks(int ifindex)
{
    for(int h=0;h<2;++h){
        int n=deployment_filter_count(ifindex,h);
        if(n<0)return die("inspect deployment classifier hooks");
        if(n){fprintf(stderr,"Deployment refused: %s has existing classifiers\n",h?"egress":"ingress");return 1;}
    }
    return 0;
}

static int parse_deployment_u32(const char *text,u32 *out,u32 maximum)
{
    char *end=NULL;errno=0;unsigned long value=strtoul(text,&end,0);
    if(errno || !*text || *text=='-' || !end || *end || !value || value>maximum)return 1;
    *out=value;return 0;
}
