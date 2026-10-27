import { fmtTs } from '../api';

describe('fmtTs', () => {
  it('renders an explicit UTC instant for a Z-suffixed timestamp', () => {
    expect(fmtTs('2026-03-02T10:00:00Z')).toBe('2026-03-02 10:00:00 UTC');
  });

  it('normalises an offset timestamp to the same UTC instant', () => {
    expect(fmtTs('2026-03-02T05:30:00-04:30')).toBe('2026-03-02 10:00:00 UTC');
  });

  // Note: offset-less (naive) strings are out of contract — the API always
  // emits tz-aware UTC timestamps — and `new Date` parses them as *local*
  // time per the ES spec, which would make such a test host-dependent.
  it('renders the same instant for different explicit offsets (viewer-timezone-independent)', () => {
    expect(fmtTs('2026-03-02T15:30:00+05:30')).toBe(fmtTs('2026-03-02T10:00:00Z'));
    expect(fmtTs('2026-03-02T02:00:00-08:00')).toBe(fmtTs('2026-03-02T10:00:00Z'));
  });

  it('returns just the date when opts.date is set', () => {
    expect(fmtTs('2026-03-02T23:59:59Z', { date: true })).toBe('2026-03-02');
    // 23:59:59+05:30 is still 2026-03-02 in UTC.
    expect(fmtTs('2026-03-02T23:59:59+05:30', { date: true })).toBe('2026-03-02');
    // 01:00:00+05:30 is 2026-03-01T19:30Z — the date must roll back to the
    // UTC day, not stay on the source-offset day.
    expect(fmtTs('2026-03-02T01:00:00+05:30', { date: true })).toBe('2026-03-01');
  });

  it('falls back to a placeholder for empty or null input', () => {
    expect(fmtTs(undefined)).toBe('time unknown');
    expect(fmtTs(null)).toBe('time unknown');
    expect(fmtTs('')).toBe('time unknown');
  });

  it('echoes the raw string when it is not a parseable date', () => {
    expect(fmtTs('not-a-date')).toBe('not-a-date');
  });
});
