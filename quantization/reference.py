"""Independent integer and exact rational references. Standard library only."""
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import struct

from validation.reference import Model as StaticModel, STAGES, prediction

ROOT = Path(__file__).resolve().parents[1]
I32_MIN, I32_MAX = -(1 << 31), (1 << 31)-1
I64_MIN, I64_MAX = -(1 << 63), (1 << 63)-1
MAGIC, VERSION = 0x4C535031, 1


class ArithmeticFailure(ValueError):
    def __init__(self, code, detail):
        super().__init__(f'{code}: {detail}')
        self.code = code


def check(value, bits):
    if not -(1 << (bits-1)) <= value < (1 << (bits-1)):
        raise ArithmeticFailure('overflow', f'int{bits}: {value}')
    return value


def round_div(value, divisor):
    """Nearest-even, symmetric in sign, using arbitrary-precision integers."""
    if divisor <= 0:
        raise ArithmeticFailure('configuration', 'positive divisor required')
    whole, remainder = divmod(abs(value), divisor)
    if remainder*2 > divisor or (remainder*2 == divisor and whole % 2):
        whole += 1
    return -whole if value < 0 else whole


def shift(value, bits):
    if not 0 <= bits <= 62:
        raise ArithmeticFailure('configuration', 'shift must be 0..62')
    return check(round_div(check(value, 64), 1 << bits), 32)


def linear(weights, inputs, rows, bits):
    if len(weights) != rows*len(inputs) or not inputs:
        raise ArithmeticFailure('configuration', 'linear shape')
    output = []
    for i in range(rows):
        accumulator = 0
        for j, value in enumerate(inputs):
            product = check(weights[i*len(inputs)+j], 32)*check(value, 32)
            accumulator = check(accumulator+product, 64)
        output.append(shift(accumulator, bits))
    return output


def normalize(raw, mean, scale, q, limits):
    if not len(raw) == len(mean) == len(scale) == len(limits) == 6 or not 0 <= q <= 24:
        raise ArithmeticFailure('configuration', 'normalization shape/exponent')
    result = []
    for x, mu, sigma, limit in zip(raw, mean, scale, limits):
        check(x, 64); check(mu, 64)
        if not 0 < sigma <= I64_MAX or not 0 < limit <= I64_MAX:
            raise ArithmeticFailure('configuration', 'invalid scale/domain')
        delta = x-mu
        if abs(delta) > limit:
            raise ArithmeticFailure('range', 'raw feature outside calibrated domain')
        # Algebraically independent of C's quotient/remainder decomposition.
        result.append(check(round_div(delta*(1 << q), sigma), 32))
    return result


@dataclass
class LayerModel:
    source: StaticModel
    config: dict

    @classmethod
    def load(cls, config_path=None, source_path=None):
        import json
        config_path = config_path or ROOT/'quantization/calibrated.json'
        source_path = Path(source_path or ROOT/'src/mlp_params.bpf.h')
        cfg = json.loads(Path(config_path).read_text())
        if cfg['source_header_sha256'] != hashlib.sha256(source_path.read_bytes()).hexdigest():
            raise ArithmeticFailure('configuration', 'source model hash mismatch')
        obj = cls(StaticModel.load(source_path), cfg)
        obj.validate()
        if cfg.get('parameter_sha256') != hashlib.sha256(obj.packed()).hexdigest():
            raise ArithmeticFailure('configuration', 'experimental parameter hash mismatch')
        return obj

    def validate(self):
        c = self.config
        if (c['schema'] != VERSION or not 0 <= c['q_normalized'] <= 24
                or c['q_weights'] != [16]*3 or len(c['q_outputs']) != 3
                or len(c['delta_limits']) != 6):
            raise ArithmeticFailure('configuration', 'unsupported model metadata')
        qx = c['q_normalized']
        for qw, qz in zip(c['q_weights'], c['q_outputs']):
            if not 0 <= qz <= 30 or not 0 <= qx+qw-qz <= 62:
                raise ArithmeticFailure('configuration', 'unsupported scale transition')
            qx = qz

    @property
    def mean(self): return self.source.mean

    @property
    def scale(self): return self.source.scale

    @property
    def exponents(self):
        a, b, c = self.config['q_outputs']
        return [self.config['q_normalized'], a, a, b, b, c]

    def metadata(self):
        c = self.config
        return struct.pack('<10I6Q', MAGIC, VERSION, c['q_normalized'],
                           *c['q_weights'], *c['q_outputs'], 0, *c['delta_limits'])

    def packed(self): return self.source.packed()+self.metadata()

    def infer(self, raw, events=None):
        self.validate()
        try:
            values = [normalize(raw, self.mean, self.scale, self.config['q_normalized'], self.config['delta_limits'])]
            qx = self.config['q_normalized']
            for i, rows in enumerate((32, 32, 2)):
                qz = self.config['q_outputs'][i]
                values.append(linear(self.source.weights[i], values[-1], rows, qx+16-qz))
                if i < 2: values.append([max(0, v) for v in values[-1]])
                qx = qz
        except ArithmeticFailure as error:
            if events is not None: events.append(dict(kind=error.code, detail=str(error)))
            raise
        return dict(zip(STAGES, values)), prediction(values[-1])


class ExactModel:
    """Exact rational network represented by the Q16 header, NOT original FP32.

    One common denominator avoids floating errors and per-product Fractions.
    """
    def __init__(self, source):
        self.source = source
        self.denominator = math.lcm(*source.scale)

    def infer(self, raw):
        denominator = self.denominator
        values = [(x-mu)*(denominator//sigma) for x, mu, sigma in
                  zip(raw, self.source.mean, self.source.scale)]
        numerators, denominators = [values], [denominator]
        for weights, rows in zip(self.source.weights, (32, 32, 2)):
            columns = len(values)
            values = [sum(weights[i*columns+j]*v for j, v in enumerate(values)) for i in range(rows)]
            denominator *= 65536
            numerators.append(values); denominators.append(denominator)
            if rows != 2:
                values = [max(v, 0) for v in values]
                numerators.append(values); denominators.append(denominator)
        return dict(zip(STAGES, numerators)), dict(zip(STAGES, denominators)), prediction(values)
