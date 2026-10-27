"""ctypes adapter for the offline compilation of original C source."""
import ctypes as C
from reference import SIZES, STAGES

I32, I64 = C.c_int32, C.c_int64


class Native:
    def __init__(self, path):
        self.lib = C.CDLL(str(path))
        signatures = {
            "native_reset": ([], None), "native_capacity": ([C.c_int], None),
            "native_normalize": ([C.POINTER(I64), C.POINTER(I32), C.POINTER(I64), C.POINTER(I64), C.c_int], None),
            "native_linear": ([C.POINTER(I32), C.POINTER(I32), C.POINTER(I32), C.c_int, C.c_int], None),
            "native_relu": ([C.POINTER(I32), C.c_int], None),
            "native_mlp": ([C.POINTER(I64), C.POINTER(I32)], C.c_int),
            "native_packet": ([C.c_void_p, C.c_size_t, C.c_uint64], C.c_int),
            "native_flow": ([C.c_int, C.POINTER(I64)], C.c_int),
            "native_snapshot": ([C.POINTER(I32)], None),
            "native_classify": ([I32, I32], C.c_int),
            "native_call_count": ([C.c_int], C.c_int),
        }
        for name in ("flow_count", "prediction_count", "label", "stage_mask"):
            signatures["native_" + name] = ([], C.c_int)
        for name, (args, result) in signatures.items():
            fn = getattr(self.lib, name)
            fn.argtypes, fn.restype = args, result
        self.lib.native_reset()

    def normalize(self, x, mean, scale):
        n = len(x)
        out = (I32 * n)()
        self.lib.native_normalize((I64 * n)(*x), out, (I64 * n)(*mean), (I64 * n)(*scale), n)
        return list(out)

    def linear(self, weights, x, rows):
        out = (I32 * rows)()
        self.lib.native_linear((I32 * len(weights))(*weights), (I32 * len(x))(*x), out, rows, len(x))
        return list(out)

    def relu(self, x):
        out = (I32 * len(x))(*x)
        self.lib.native_relu(out, len(x))
        return list(out)

    def infer(self, raw):
        out = (I32 * 192)()
        label = self.lib.native_mlp((I64 * 6)(*raw), out)
        return {name: list(out[i * 32:i * 32 + n]) for i, (name, n) in enumerate(zip(STAGES, SIZES))}, label

    def packet(self, data, ns):
        buf = C.create_string_buffer(data)
        return self.lib.native_packet(buf, len(data), ns)

    def flows(self):
        result = []
        for i in range(self.lib.native_flow_count()):
            out = (I64 * 8)()
            if self.lib.native_flow(i, out):
                raise RuntimeError("missing host flow")
            result.append(list(out))
        return result

    def snapshots(self):
        out = (I32 * 192)()
        self.lib.native_snapshot(out)
        return {name: list(out[i * 32:i * 32 + n]) for i, (name, n) in enumerate(zip(STAGES, SIZES))}
