import test from 'ava';
import { sum } from '../index';

test('sum native ts', (t) => {
  t.is(sum(1, 2), 3);
});
