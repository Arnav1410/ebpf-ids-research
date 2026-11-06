"""Independent AF_PACKET witness, used only on the runner-owned server veth.

No BPF helpers, model code or flow-key C helper is reused here. Capture timing
cannot be substituted for bpf_ktime_get_ns at the TC hook.
"""
import json
from pathlib import Path
import socket
import struct
import sys


def compare_snapshot(snapshot,witness,port,count):
    """Compare actual TC records with independent packet observations.

    This deliberately excludes IAT: capture and TC timestamps differ.
    """
    if witness['capture_drops']:raise RuntimeError('AF_PACKET capture dropped packets')
    if len(snapshot['flows'])!=count or len(snapshot['results'])!=count:raise RuntimeError('Unexpected logical flow/result count')
    comparisons=[]
    for source_port in range(port,port+count):
        incoming=[p for p in witness['packets'] if p['hook']=='ingress' and
                  (p['source_ip'],p['dest_ip'],p['source_port'],p['dest_port'])==('33.33.33.73','33.33.33.1',source_port,5001)]
        outgoing=[p for p in witness['packets'] if p['hook']=='egress' and
                  (p['source_ip'],p['dest_ip'],p['source_port'],p['dest_port'])==('33.33.33.1','33.33.33.73',5001,source_port)]
        if not incoming or not outgoing:raise RuntimeError('Witness missed a controlled traffic direction')
        flow=next(f for f in snapshot['flows'] if f['source_port']==source_port)
        record=next(r for r in snapshot['results'] if r['source_port']==source_port)
        key=dict(a_ip='33.33.33.1',a_port=5001,b_ip='33.33.33.73',b_port=source_port,protocol=6)
        if flow['key']!=key or record['key']!=key:raise RuntimeError('Canonical key mismatch')
        for hook,packets in (('ingress',incoming),('egress',outgoing)):
            stats=flow['hooks'][hook]
            if stats['packets']!=len(packets) or stats['bytes']!=sum(p['skb_bytes'] for p in packets):
                raise RuntimeError(f'AF_PACKET/TC {hook} counters disagree for {source_port}')
        if flow['endpoint_packets']!=[len(outgoing),len(incoming)]:raise RuntimeError('Endpoint directions confused with hook direction')
        if flow['endpoint_bytes']!=[sum(p['skb_bytes'] for p in outgoing),sum(p['skb_bytes'] for p in incoming)]:
            raise RuntimeError('Endpoint byte counters disagree')
        if flow['packets']!=len(incoming) or flow['bytes']!=sum(p['segment_bytes'] for p in incoming):
            raise RuntimeError('Monitoring bytes contaminated MLP counters')
        if not flow['input_initialized'] or flow['mlp_input_direction']!=1 or record['mlp_input_direction']!=1:
            raise RuntimeError('MLP leg identity disagrees with controlled ingress direction')
        prefix=[]
        for packet in incoming:
            prefix.append(packet)
            if packet['tcp_flags']&5:break
        else:raise RuntimeError('No witnessed ingress FIN/RST trigger')
        expected=[max(p['segment_bytes'] for p in prefix),None,min(p['segment_bytes'] for p in prefix),5001,
                  sum(p['tcp_header_bytes'] for p in prefix),len(prefix)]
        if any(record['features'][i]!=expected[i] for i in (0,2,3,4,5)):
            raise RuntimeError(f'Independent ingress feature mismatch for {source_port}')
        comparisons.append(dict(source_port=source_port,key=key,ingress_packets=len(incoming),
            ingress_bytes=flow['hooks']['ingress']['bytes'],egress_packets=len(outgoing),egress_bytes=flow['hooks']['egress']['bytes'],
            expected_non_timing_features=expected,kernel_features=record['features'],status='PASS',
            iat_comparison='NOT TESTED: AF_PACKET timestamps are not TC helper samples'))
    if sum(c['ingress_packets'] for c in comparisons)!=snapshot['matched'] or sum(c['egress_packets'] for c in comparisons)!=snapshot['egress_matched']:
        raise RuntimeError('Witness/global matched counters disagree')
    return dict(status='PASS',flows=count,non_timing_features_checked=5*count,comparisons=comparisons,
                counter_basis='Independent AF_PACKET observations in this isolated small-packet test; not general offload equivalence')


def parse_frame(frame, direction):
    if len(frame)<54 or frame[12:14]!=b'\x08\x00': return None
    ihl=(frame[14]&15)*4
    total=int.from_bytes(frame[16:18],'big')
    if frame[14]>>4!=4 or ihl<20 or ihl>60 or frame[23]!=6: return None
    if int.from_bytes(frame[20:22],'big')&0x3fff or total<ihl+20 or len(frame)<14+total:return None
    offset=14+ihl;header=(frame[offset+12]>>4)*4
    if header<20 or header>60 or total<ihl+header:return None
    source,destination=socket.inet_ntoa(frame[26:30]),socket.inet_ntoa(frame[30:34])
    sport,dport=struct.unpack_from('!HH',frame,offset)
    return dict(hook=direction,source_ip=source,source_port=sport,dest_ip=destination,dest_port=dport,
                skb_bytes=len(frame),segment_bytes=total-ihl,tcp_header_bytes=header,
                tcp_flags=frame[offset+13],sequence=int.from_bytes(frame[offset+4:offset+8],'big'))


def main():
    interface,directory=sys.argv[1],Path(sys.argv[2])
    if interface!='tcids-s0':raise RuntimeError('Witness is restricted to the isolated test interface')
    packets=[]
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as capture:
        capture.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1<<20)
        capture.bind((interface,0));capture.settimeout(.05)
        (directory/'witness.ready').write_text('ready\n')
        while not (directory/'witness.stop').exists():
            try:frame,address=capture.recvfrom(65535)
            except socket.timeout:continue
            packet=parse_frame(frame,'egress' if address[2]==4 else 'ingress')
            if packet:packets.append(packet)
        # PACKET_STATISTICS: struct tpacket_stats { unsigned packets, drops; }.
        delivered,drops=struct.unpack('II',capture.getsockopt(263,6,8))
    (directory/'packets.json').write_text(json.dumps(dict(packets=packets,capture_packets=delivered,
        capture_drops=drops,basis='AF_PACKET skb observations; timing is not TC helper timing'),indent=2)+'\n')


if __name__=='__main__':main()
