"""ctypes adapter for the shared experimental arithmetic header."""
import ctypes as C
from validation.reference import STAGES, SIZES
from quantization.reference import ArithmeticFailure


class Native:
    def __init__(self, path):
        self.lib = C.CDLL(str(path))
        i32, i64, u64 = C.c_int32, C.c_int64, C.c_uint64
        signatures = {
            'ls_native_mlp': ([C.POINTER(i64), C.POINTER(i32), C.POINTER(i32)], C.c_int),
            'ls_native_shift': ([i64, C.c_uint32, C.POINTER(i32)], C.c_int),
            'ls_native_add': ([i64, i64, C.POINTER(i64)], C.c_int),
            'ls_native_linear': ([C.POINTER(i32), C.POINTER(i32), C.POINTER(i32), C.c_int, C.c_int, C.c_uint32], C.c_int),
            'ls_native_normalize': ([C.POINTER(i64), C.POINTER(i64), C.POINTER(i64), C.c_uint32, C.POINTER(u64), C.POINTER(i32)], C.c_int),
            'ls_native_packed': ([C.POINTER(C.c_ubyte)], C.c_uint),
            'ls_native_invalid_metadata': ([C.c_int], None),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.lib, name); fn.argtypes = args; fn.restype = result
        self.lib.ls_native_reset()

    def infer(self, raw):
        out = (C.c_int32*192)(); label = C.c_int32()
        code = self.lib.ls_native_mlp((C.c_int64*6)(*raw), out, C.byref(label))
        if code: raise ArithmeticFailure({1:'configuration',2:'range',3:'overflow'}[code], 'host C rejected inference')
        return {stage:list(out[i*32:i*32+n]) for i,(stage,n) in enumerate(zip(STAGES,SIZES))},label.value
