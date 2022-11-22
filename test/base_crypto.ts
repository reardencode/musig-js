import * as base from '../base_crypto';
import * as vectors from './base_vectors.json';

describe('Base Crypto', function () {
  beforeAll(function () {});

  for (const { hex, isXOnlyPoint, isPoint, pointNegate, hasEvenY, pointX } of vectors.point) {
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
    it('pointX', function () {
      if (pointX === null) {
        expect(() => base.pointX(point)).toThrow();
      } else {
        expect(Buffer.from(base.pointX(point)).toString('hex')).toBe(pointX);
      }
    });
  }

  // TODO: Add tests for isSecret
  for (const { hex, isScalar, bHex, sum, product, negated, remainder } of vectors.secret) {
    const secret = Buffer.from(hex, 'hex');
    const b = Buffer.from(bHex, 'hex');
    it('isScalar', function () {
      expect(base.isScalar(secret)).toBe(isScalar);
    });
    it('scalarAdd', function () {
      if (sum === null) {
        expect(() => base.scalarAdd(secret, b)).toThrow();
      } else {
        expect(Buffer.from(base.scalarAdd(secret, b)).toString('hex')).toBe(sum);
      }
    });
    it('scalarMultiply', function () {
      if (sum === null) {
        expect(() => base.scalarMultiply(secret, b)).toThrow();
      } else {
        expect(Buffer.from(base.scalarMultiply(secret, b)).toString('hex')).toBe(product);
      }
    });
    it('scalarNegate', function () {
      if (negated === null) {
        expect(() => base.scalarNegate(secret)).toThrow();
      } else {
        expect(Buffer.from(base.scalarNegate(secret)).toString('hex')).toBe(negated);
      }
    });
    it('scalarMod', function () {
      if (remainder === null) {
        expect(() => base.scalarMod(secret)).toThrow();
      } else {
        expect(Buffer.from(base.scalarMod(secret)).toString('hex')).toBe(remainder);
      }
    });
  }
});
