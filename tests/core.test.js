const test = require('node:test');
const assert = require('node:assert/strict');

const { extractFeatures, computeRiskScore, analyzeUPIIntent } = require('../logic.js');
const { evaluateUrl } = require('../mule-phish-guard/heuristics.js');

test('safe bank URL is treated as low risk', () => {
  const features = extractFeatures('https://onlinesbi.sbi');
  assert.equal(features.isExactLegit, true);
  assert.ok(computeRiskScore(features) < 20);
});

test('suspicious phishing URL is detected as malicious', () => {
  const features = extractFeatures('http://sbi-secure-login.xyz/verify-account');
  assert.equal(features.isTyposquat, true);
  const riskScore = computeRiskScore(features);
  assert.ok(riskScore > 45, `Expected risk > 45 but got ${riskScore}`);
});

test('UPI intent spoofing is flagged as malicious', () => {
  const result = analyzeUPIIntent('upi://pay?pa=scammer88@ybl&pn=State%20Electricity%20Board&am=15000.00&tn=OTP%20required%20now&cu=INR');
  assert.equal(result.isValid, true);
  assert.equal(result.isMalicious, true);
  assert.ok(result.riskIndicators.length > 0);
});

test('malformed UPI params do not crash the decoder', () => {
  const result = analyzeUPIIntent('upi://pay?pa=bad%ZZ@ybl&pn=State%20Electricity%20Board&am=15000.00&tn=urgent%2&cu=INR');
  assert.equal(result.isValid, true);
  assert.ok(result.details.pa.includes('bad%ZZ') || result.details.pa === 'bad%ZZ@ybl');
});

test('extension heuristic catches bare phishing domains without a protocol', () => {
  const result = evaluateUrl('sbi-secure-login.xyz/verify-account');
  assert.ok(result.band === 'HIGH' || result.score >= 55, `Unexpected result: ${JSON.stringify(result)}`);
});
