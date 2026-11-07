"""Read only the bounded numeric NPY formats supplied with this repository."""
import ast
import hashlib
import math
from pathlib import Path
import struct


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def numeric_npy(path):
    with Path(path).open('rb') as f:
        if f.read(8)!=b'\x93NUMPY\x01\x00':raise ValueError('Only numeric NPY v1 supported; no pickle')
        size=struct.unpack('<H',f.read(2))[0]
        if size>4096:raise ValueError('NPY header too large')
        h=ast.literal_eval(f.read(size).decode('latin1'))
        if h.get('descr') not in ('<i8','<f8') or h.get('fortran_order') is not False:raise ValueError('Unsafe/unsupported NPY dtype/order')
        shape=h.get('shape')
        if not isinstance(shape,tuple) or not 1<=len(shape)<=2 or any(type(n) is not int or not 0<n<=1000000 for n in shape):raise ValueError('Invalid NPY shape')
        count=math.prod(shape)
        if count>6000000:raise ValueError('NPY size exceeds evaluation limit')
        data=f.read(count*8+1)
        if len(data)!=count*8:raise ValueError('Truncated/trailing NPY data')
    code='q' if h['descr']=='<i8' else 'd';values=[x[0] for x in struct.iter_unpack('<'+code,data)]
    if any(not math.isfinite(x) for x in values):raise ValueError('Non-finite NPY value')
    return h,values


def reproduction(root):
    data=root/'dataset/reproduction-xdp-data.npy';label=root/'dataset/reproduction-xdp-label.npy'
    h,values=numeric_npy(data);lh,labels=numeric_npy(label)
    if h['descr']!='<i8' or len(h['shape'])!=2 or h['shape'][1]!=6 or lh['shape']!=(h['shape'][0],):raise ValueError('Dataset/label shape mismatch')
    if any(y not in (0,1) for y in labels):raise ValueError('Unsupported encoded class label')
    return [values[i:i+6] for i in range(0,len(values),6)],[int(y) for y in labels]
