import * as base from '../base_crypto';
import * as vectors from './base_vectors.json';

describe('Base Crypto', function () {
  beforeAll(function () {});

  for (const {
    hex,
    isXOnlyPoint,
    isPoint,
    pointNegate,
    hasEvenY,
    pointCompress,
    pointX,
  } of vectors.point) {
    const point = Buffer.from(hex, 'hex');
    it('isXOnlyPoint', function () {
      expect(base.isXOnlyPoint(point)).toBe(isXOnlyPoint);
    });
    it('isPoint', function () {
      expect(base.isPoint(point)).toBe(isPoint);
    });
    if (point.length === 32) {
      const evenPoint = Buffer.concat([Uint8Array.of(2), point]);
      it('isEvenPoint', function () {
        expect(base.isPoint(evenPoint)).toBe(isXOnlyPoint);
      });
      const oddPoint = Buffer.concat([Uint8Array.of(3), point]);
      it('isOddPoint', function () {
        expect(base.isPoint(oddPoint)).toBe(isXOnlyPoint);
      });
      it('oddEvenNegate', function () {
        expect(Buffer.from(base.pointNegate(evenPoint))).toEqual(oddPoint);
        expect(Buffer.from(base.pointNegate(oddPoint))).toEqual(evenPoint);
      });
      it('oddEvenPointX', function () {
        expect(Buffer.from(base.pointX(evenPoint))).toEqual(point);
        expect(Buffer.from(base.pointX(oddPoint))).toEqual(point);
      });
    }
    it('pointNegate', function () {
      if (pointNegate === null) {
        expect(() => base.pointNegate(point)).toThrow();
      } else {
        expect(Buffer.from(base.pointNegate(point)).toString('hex')).toBe(pointNegate);
      }
    });
    it('hasEvenY', function () {
      if (hasEvenY === null) {
        expect(() => base.hasEvenY(point)).toThrow();
      } else {
        expect(base.hasEvenY(point)).toBe(hasEvenY);
      }
    });
    it('pointCompress', function () {
      if (pointCompress === null) {
        expect(() => base.pointCompress(point)).toThrow();
      } else {
        expect(Buffer.from(base.pointCompress(point)).toString('hex')).toBe(pointCompress);
      }
    });
    it('pointX', function () {
      if (pointX === null) {
        expect(() => base.pointX(point)).toThrow();
      } else {
        expect(Buffer.from(base.pointX(point)).toString('hex')).toBe(pointX);
      }
    });
  }

  for (const { hex, isSecret, bHex, sum, product, negated, remainder } of vectors.secret) {
    const secret = Buffer.from(hex, 'hex');
    const b = Buffer.from(bHex, 'hex');
    it('isSecret', function () {
      expect(base.isSecret(secret)).toBe(isSecret);
    });
    it('secretAdd', function () {
      if (sum === null) {
        expect(() => base.secretAdd(secret, b)).toThrow();
      } else {
        expect(Buffer.from(base.secretAdd(secret, b)).toString('hex')).toBe(sum);
      }
    });
    it('secretMultiply', function () {
      if (sum === null) {
        expect(() => base.secretMultiply(secret, b)).toThrow();
      } else {
        expect(Buffer.from(base.secretMultiply(secret, b)).toString('hex')).toBe(product);
      }
    });
    it('secretNegate', function () {
      if (negated === null) {
        expect(() => base.secretNegate(secret)).toThrow();
      } else {
        expect(Buffer.from(base.secretNegate(secret)).toString('hex')).toBe(negated);
      }
    });
    it('secretMod', function () {
      if (remainder === null) {
        expect(() => base.secretMod(secret)).toThrow();
      } else {
        expect(Buffer.from(base.secretMod(secret)).toString('hex')).toBe(remainder);
      }
    });
  }
});
