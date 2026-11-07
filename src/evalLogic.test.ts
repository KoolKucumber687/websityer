import test from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLE_DATASET, computeEvaluationMetrics, evaluateThreatLevel } from './evalLogic.ts';

test('dataset contains required categories and multi-language cases', () => {
  assert.equal(SAMPLE_DATASET.length >= 6, true);
  const languages = new Set(SAMPLE_DATASET.map(c => c.language));
  assert.equal(languages.has('EN'), true);
  assert.equal(languages.has('ES'), true);
  assert.equal(languages.has('FR'), true);
});

test('evaluates threat level accurately for grandparent emergency', () => {
  const result = evaluateThreatLevel("Grandma, it's me! I'm in jail. Please send $2,000 in gift cards.");
  assert.equal(result.isThreat, true);
  assert.equal(result.score > 0.9, true);
});

test('computes precision, recall, and false alarms correctly', () => {
  const predictions: Record<string, boolean> = {
    'CASE-01': true,
    'CASE-02': true,
    'CASE-03': true,
    'CASE-04': true,
    'CASE-05': true,
    'CASE-06': false,
  };
  const metrics = computeEvaluationMetrics(SAMPLE_DATASET, predictions);
  assert.equal(metrics.falseAlarms, 0);
  assert.equal(metrics.precision, 1);
  assert.equal(metrics.recall, 1);
  assert.equal(metrics.f1Score, 1);
});
