import test from 'ava';
import { mul } from '../index';

test('mul native', (t) => {
  t.is(mul(20, 23), 20 * 23);
});
