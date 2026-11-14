/* Test-only userspace driver. Original BPF source/bytecode is uninstrumented.
 * No attach, pin, trace reader or networking configuration API is used. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
typedef int64_t s64;typedef int32_t s32;typedef uint64_t u64;
#define __uint(n,v) int (*n)[v]
#define __type(n,v) v *n
#define SEC(n)
#define LIBBPF_PIN_BY_NAME 1
#include "../../src/common.h"
#include "../../src/params.bpf.h"
static const char *names[]={"xdp_preprocessing","xdp_input_linear","xdp_input_relu","xdp_hidden_linear","xdp_hidden_relu","xdp_output_linear","xdp_prog"};
static int fds[7],flow_fd,tail_fd;static uint32_t ids[7];static s64 nonce;
static int error(const char *s){fprintf(stderr,"%s: %s (%d)\n",s,strerror(errno),errno);return -1;}
static int tail_state(int populated,int missing)
{
 for(uint32_t i=0;i<6;i++){
  if(populated && (int)i!=missing){if(bpf_map_update_elem(tail_fd,&i,&fds[i],BPF_ANY))return error("set private tail target");}
  else if(bpf_map_delete_elem(tail_fd,&i) && errno!=ENOENT)return error("clear private tail target");
 }
 for(uint32_t i=0;i<6;i++){
  uint32_t value=0;int ret=bpf_map_lookup_elem(tail_fd,&i,&value);
  if(populated && (int)i!=missing){if(ret||value!=ids[i]){errno=EPROTO;return error("tail ID mismatch");}}
  else if(!ret || errno!=ENOENT){errno=EPROTO;return error("tail target not empty");}
 }
 return 0;
}
static void vector(const s32 *x,int n){printf("[");for(int j=0;j<n;j++)printf("%s%d",j?",":"",x[j]);printf("]");}
static void state(const struct flow_attribute *a)
{
 printf("{\"features\":[%lld,%lld,%lld,%lld,%lld,%lld],\"model_slot\":%d,\"nonce\":%lld,\"hidden1\":",
 (long long)a->max_packet_length,(long long)a->max_duration,(long long)a->min_packet_length,(long long)a->dst_port,(long long)a->header_length,(long long)a->num_packet,a->nn_idx,(long long)a->status);
 vector(a->hidden1,32);printf(",\"hidden2\":");vector(a->hidden2,32);
 printf(",\"prediction_derived\":%d}",a->hidden1[0]>a->hidden1[1]?0:1);
}
static uint16_t checksum(const unsigned char *p,int n)
{uint32_t s=0;for(int i=0;i<n;i+=2)s+=((uint32_t)p[i]<<8)|(i+1<n?p[i+1]:0);while(s>>16)s=(s&65535)+(s>>16);return (uint16_t)~s;}
static int seed(const s64 raw[6],struct flow *key,struct flow_attribute *a,unsigned char packet[54],int bad_model)
{
 if(raw[3]<0||raw[3]>65535||raw[5]<=0){errno=EINVAL;return error("unsupported port/packet count");}
 memset(packet,0,54);packet[12]=8;packet[14]=0x45;packet[17]=40;packet[22]=64;packet[23]=6;
 packet[26]=33;packet[27]=33;packet[28]=33;packet[29]=73;
 packet[30]=33;packet[31]=33;packet[32]=33;packet[33]=1;
 packet[34]=49500>>8;packet[35]=49500&255;packet[36]=raw[3]>>8;packet[37]=raw[3]&255;packet[46]=0x50;packet[47]=0x10;
 uint16_t c=checksum(packet+14,20);packet[24]=c>>8;packet[25]=c&255;
 unsigned char pseudo[32]={};memcpy(pseudo,packet+26,8);pseudo[9]=6;pseudo[11]=20;memcpy(pseudo+12,packet+34,20);
 c=checksum(pseudo,32);packet[50]=c>>8;packet[51]=c&255;
 memset(key,0,sizeof(*key));memcpy(&key->saddr,packet+26,4);memcpy(&key->daddr,packet+30,4);
 key->sport=htons(49500);key->dport=htons((uint16_t)raw[3]);
 memset(a,0,sizeof(*a));a->max_packet_length=raw[0];a->max_duration=raw[1];a->min_packet_length=raw[2];a->dst_port=raw[3];a->header_length=raw[4];a->num_packet=raw[5];
 a->nn_idx=bad_model?-1:0;a->status=++nonce;
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return error("monotonic clock");
 a->detection_start_time=(u64)t.tv_sec*1000000000ULL+t.tv_nsec;
 for(int i=0;i<32;i++){a->hidden1[i]=0x5a123400+i;a->hidden2[i]=-0x5a123400-i;}
 if(bpf_map_delete_elem(flow_fd,key)&&errno!=ENOENT)return error("remove old private key");
 if(bpf_map_update_elem(flow_fd,key,a,BPF_NOEXIST))return error("seed private flow");
 struct flow_attribute observed;if(bpf_map_lookup_elem(flow_fd,key,&observed)||memcmp(a,&observed,sizeof(*a)))return error("seed readback");
 return 0;
}
static int invoke(int stage,int cpu,const unsigned char packet[54],uint32_t *duration)
{
 unsigned char out[128]={};LIBBPF_OPTS(bpf_test_run_opts,o,.data_in=packet,.data_size_in=54,.data_out=out,.data_size_out=128,.repeat=1,.flags=0);
 if(sched_getcpu()!=cpu||bpf_prog_test_run_opts(fds[stage],&o)||o.retval!=XDP_PASS||o.data_size_out!=54||memcmp(out,packet,54)){errno=EPROTO;return error("original XDP test-run failed");}
 if(!o.duration||o.duration==UINT32_MAX){errno=ERANGE;return error("invalid duration");}
 *duration=o.duration;return 0;
}
static int serve(void)
{
 cpu_set_t allowed;CPU_ZERO(&allowed);if(sched_getaffinity(0,sizeof(allowed),&allowed))return error("affinity");
 printf("{\"event\":\"benchmark_ready\",\"mode\":\"xdp_q16\",\"network_attachments\":false,\"allowed_cpus\":[");
 int n=0;for(int i=0;i<CPU_SETSIZE;i++)if(CPU_ISSET(i,&allowed))printf("%s%d",n++?",":"",i);printf("]}\n");fflush(stdout);
 char line[1024];while(fgets(line,sizeof(line),stdin)){
  if(!strcmp(line,"stop\n"))return 0;
  char op[24],extra;int cpu,kind,warm,samples;long long input[6];
  if(sscanf(line,"%23s %d %d %d %d %lld %lld %lld %lld %lld %lld %c",op,&cpu,&kind,&warm,&samples,&input[0],&input[1],&input[2],&input[3],&input[4],&input[5],&extra)!=11){errno=EINVAL;return error("invalid command");}
  if(cpu<0||cpu>=CPU_SETSIZE||!CPU_ISSET(cpu,&allowed)||warm<0||samples<1||warm+samples>3){errno=EINVAL;return error("command bounds");}
  cpu_set_t set;CPU_ZERO(&set);CPU_SET(cpu,&set);if(sched_setaffinity(0,sizeof(set),&set))return error("pin controller only");
  int isolated=!strcmp(op,"isolated"),failure=!strcmp(op,"failure");
  if(!isolated&&!failure&&strcmp(op,"measure")){errno=EINVAL;return error("unknown command");}
  if(failure&&(kind<1||kind>7)){errno=EINVAL;return error("unknown negative control");}
  if((isolated||failure)&&(warm||samples!=1)){errno=EINVAL;return error("diagnostic count");}
  if((isolated||failure) && tail_state(!isolated,failure&&kind<=5?kind:-1))return -1;
  s64 raw[6];for(int i=0;i<6;i++)raw[i]=input[i];
  struct flow_attribute observed[6];uint32_t times[3]={};int present=1;
  for(int iteration=0;iteration<warm+samples;iteration++){
   struct flow key;struct flow_attribute initial;unsigned char packet[54];
   if(seed(raw,&key,&initial,packet,failure&&kind==7))return -1;
   if(failure&&kind==6){if(bpf_map_delete_elem(flow_fd,&key))return error("negative flow delete");present=0;}
   for(int j=0;j<(isolated?6:1);j++){
    uint32_t dt;if(invoke(isolated?j:0,cpu,packet,&dt))return -1;
    if(present){
     struct flow_attribute *v=&observed[isolated?j:iteration];
     if(bpf_map_lookup_elem(flow_fd,&key,v))return error("result readback");
     if(v->status!=initial.status||v->nn_idx!=initial.nn_idx||v->max_packet_length!=raw[0]||v->max_duration!=raw[1]||v->min_packet_length!=raw[2]||v->dst_port!=raw[3]||v->header_length!=raw[4]||v->num_packet!=raw[5]){errno=EPROTO;return error("feature/nonce corruption");}
    }else{struct flow_attribute v;if(!bpf_map_lookup_elem(flow_fd,&key,&v)||errno!=ENOENT){errno=EPROTO;return error("unexpected negative flow");}}
    if(!isolated&&iteration>=warm)times[iteration-warm]=dt;
   }
   if(bpf_map_delete_elem(flow_fd,&key)&&errno!=ENOENT)return error("release private key");
  }
  if((isolated||failure) && tail_state(1,-1))return -1;
  printf("{\"event\":\"xdp_block\",\"mode\":\"xdp_q16\",\"operation\":\"%s\",\"kind\":%d,\"cpu\":%d,\"warmup\":%d,\"samples\":%d,\"kernel_repeat\":1,\"flags\":0,\"packet_dport\":%lld,\"calls\":%d,\"flow_present\":%s,\"duration_ns\":[",op,kind,cpu,warm,samples,input[3],isolated?6:warm+samples,present?"true":"false");
  if(!isolated&&!failure)for(int i=0;i<samples;i++)printf("%s%u",i?",":"",times[i]);
  printf("],\"entry_program_id\":%u,\"states\":[",ids[0]);if(present)for(int i=0;i<(isolated?6:warm+samples);i++){if(i)printf(",");state(&observed[i]);}printf("]}\n");fflush(stdout);
 }
 return ferror(stdin)?error("read commands"):0;
}
int main(int argc,char **argv)
{
 if(argc!=5||(strcmp(argv[1],"--inspect")&&strcmp(argv[1],"--serve"))){fprintf(stderr,"Usage: xdp_runner --inspect|--serve OBJECT LOGDIR MODEL_BIN\n");return 2;}
 int execute=!strcmp(argv[1],"--serve"),rc=1;if(execute&&geteuid()){fprintf(stderr,"Explicitly approved root invocation required\n");return 2;}
 setvbuf(stdout,NULL,_IOLBF,0);char *logs[8]={};const size_t cap=4*1024*1024;
 for(int i=0;i<8;i++)if(!(logs[i]=calloc(1,cap)))goto done;
 LIBBPF_OPTS(bpf_object_open_opts,o,.kernel_log_buf=logs[7],.kernel_log_size=cap,.kernel_log_level=1);
 struct bpf_object *obj=bpf_object__open_file(argv[2],&o);if(!obj||libbpf_get_error(obj)){error("open original object");goto done;}
 struct bpf_map *map;struct bpf_program *p;int nm=0,np=0;
 bpf_object__for_each_map(map,obj){if(bpf_map__set_pin_path(map,NULL)||bpf_map__pin_path(map)){error("disable pin paths");goto close;}nm++;}
 bpf_object__for_each_program(p,obj)np++;
 if(nm!=5||np!=7||sizeof(struct Net)!=5216){errno=EPROTO;error("original schema");goto close;}
 const char *maps[]={"flow_map","nn_parameters","nn_idx","progs"};unsigned values[]={sizeof(struct flow_attribute),sizeof(struct Net),4,4},keys[]={sizeof(struct flow),4,4,4};
 for(int i=0;i<4;i++){map=bpf_object__find_map_by_name(obj,maps[i]);enum bpf_map_type type=i==0?BPF_MAP_TYPE_HASH:i==3?BPF_MAP_TYPE_PROG_ARRAY:BPF_MAP_TYPE_ARRAY;if(!map||bpf_map__type(map)!=type||bpf_map__key_size(map)!=keys[i]||bpf_map__value_size(map)!=values[i]){errno=EPROTO;error("map ABI");goto close;}}
 for(int i=0;i<7;i++){p=bpf_object__find_program_by_name(obj,names[i]);if(!p||bpf_program__type(p)!=BPF_PROG_TYPE_XDP||bpf_program__set_log_buf(p,logs[i],cap)||bpf_program__set_log_level(p,1)){error("program schema");goto close;}}
 printf("{\"event\":\"schema\",\"programs\":7,\"maps\":5,\"flow_key_bytes\":%zu,\"flow_value_bytes\":%zu,\"model_bytes\":%zu,\"all_pin_paths_disabled\":true}\n",sizeof(struct flow),sizeof(struct flow_attribute),sizeof(struct Net));
 if(!execute){rc=0;goto close;}
 if(bpf_object__load(obj)){error("original XDP verifier/load");goto close;}
 printf("{\"event\":\"loaded\",\"program_ids\":[");
 for(int i=0;i<7;i++){p=bpf_object__find_program_by_name(obj,names[i]);fds[i]=bpf_program__fd(p);struct bpf_prog_info info={};uint32_t len=sizeof(info);if(bpf_prog_get_info_by_fd(fds[i],&info,&len)||info.type!=BPF_PROG_TYPE_XDP)goto close;ids[i]=info.id;printf("%s%u",i?",":"",info.id);}printf("],\"map_ids\":[");
 int mi=0;bpf_object__for_each_map(map,obj){struct bpf_map_info info={};uint32_t len=sizeof(info);if(bpf_map_get_info_by_fd(bpf_map__fd(map),&info,&len))goto close;printf("%s%u",mi++?",":"",info.id);}printf("]}\n");
 struct Net net;FILE *model=fopen(argv[4],"rb");if(!model){error("open new model");goto close;}
 int valid=fread(&net,1,sizeof(net),model)==sizeof(net)&&fgetc(model)==EOF;fclose(model);if(!valid){errno=EINVAL;error("model file size");goto close;}
 for(int i=0;i<6;i++)if(net.scale[i]<=0){errno=EINVAL;error("model scale");goto close;}
 int params=bpf_object__find_map_fd_by_name(obj,"nn_parameters"),idx=bpf_object__find_map_fd_by_name(obj,"nn_idx");
 for(int slot=0;slot<2;slot++){struct Net got;if(bpf_map_update_elem(params,&slot,&net,BPF_ANY)||bpf_map_lookup_elem(params,&slot,&got)||memcmp(&got,&net,sizeof(net))){error("new model byte readback");goto close;}}
 int zero=0;if(bpf_map_freeze(params)||bpf_map_update_elem(idx,&zero,&zero,BPF_ANY)||bpf_map_freeze(idx)){error("private model freeze");goto close;}
 printf("{\"event\":\"model\",\"bytes_per_slot\":5216,\"slots_verified\":2,\"active\":0}\n");
 flow_fd=bpf_object__find_map_fd_by_name(obj,"flow_map");tail_fd=bpf_object__find_map_fd_by_name(obj,"progs");if(tail_state(1,-1))goto close;
 for(int i=0;i<6;i++)printf("{\"event\":\"tail_slot\",\"slot\":%d,\"program_id\":%u,\"type\":6}\n",i,ids[i]);
 rc=serve()?1:0;if(tail_state(0,-1))rc=1;
close:bpf_object__close(obj);
done:for(int i=0;i<8;i++){if(execute&&logs[i]){char path[4096];snprintf(path,sizeof(path),"%s/verifier-%s.log",argv[3],i<7?names[i]:"btf");FILE *f=fopen(path,"wx");if(f){fputs(logs[i],f);fclose(f);}else rc=1;}free(logs[i]);}
 return rc;
}
