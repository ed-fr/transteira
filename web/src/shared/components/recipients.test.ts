import { describe, expect, it } from 'vitest';
import {
  commitFeedback,
  commitRecipients,
  commitsLeftDraft,
  joinRecipients,
  parseRecipients,
  pastedValue,
  recipientKeyAction,
  removesChip,
  splitDraft,
  splitRecipients,
} from './recipients';

describe('splitRecipients', () => {
  it('splits on commas, semicolons and line breaks, keeping duplicates and the order', () => {
    expect(splitRecipients(' a@x.example, b@x.example;\nA@x.example\r\n\n , ')).toEqual([
      'a@x.example',
      'b@x.example',
      'A@x.example',
    ]);
  });

  it('reduces "Name <address>" to the address and drops empty brackets', () => {
    expect(splitRecipients('Carol <carol@x.example>; <dave@x.example>, Nobody <>')).toEqual([
      'carol@x.example',
      'dave@x.example',
    ]);
  });

  it('gives nothing for an empty text', () => {
    expect(splitRecipients('')).toEqual([]);
    expect(splitRecipients(' ,;\n')).toEqual([]);
  });
});

describe('parseRecipients', () => {
  it('removes case-insensitive duplicates, keeping the first spelling', () => {
    expect(parseRecipients('Alice@X.example\nalice@x.example, bob@x.example')).toEqual([
      'Alice@X.example',
      'bob@x.example',
    ]);
  });
});

describe('commitRecipients', () => {
  it('appends the new addresses and reports those already in the list', () => {
    expect(commitRecipients(['a@x.example'], 'b@x.example, A@X.example; b@x.example ,c@x.example')).toEqual({
      list: ['a@x.example', 'b@x.example', 'c@x.example'],
      added: ['b@x.example', 'c@x.example'],
      duplicates: ['A@X.example', 'b@x.example'],
    });
  });

  it('keeps the list as it is for an empty draft', () => {
    const committed = ['a@x.example'];
    const commit = commitRecipients(committed, '  ');
    expect(commit).toEqual({ list: ['a@x.example'], added: [], duplicates: [] });
    expect(commit.list).not.toBe(committed);
  });

  it('accepts addresses that are not valid (shown as invalid chips)', () => {
    expect(commitRecipients([], 'nope').added).toEqual(['nope']);
  });
});

describe('joinRecipients', () => {
  it('joins with commas, parsed back to the same list', () => {
    const list = ['a@x.example', 'b@x.example'];
    expect(joinRecipients(list)).toBe('a@x.example, b@x.example');
    expect(parseRecipients(joinRecipients(list))).toEqual(list);
    expect(joinRecipients([])).toBe('');
  });
});

describe('splitDraft', () => {
  it('splits at the last separator', () => {
    expect(splitDraft('a@x.example, b@x')).toEqual({ complete: 'a@x.example,', rest: 'b@x' });
    expect(splitDraft('a@x.example;b@x.example\nc')).toEqual({
      complete: 'a@x.example;b@x.example\n',
      rest: 'c',
    });
    expect(splitDraft('a@x.example,')).toEqual({ complete: 'a@x.example,', rest: '' });
  });

  it('keeps everything in the rest without a separator', () => {
    expect(splitDraft('a@x')).toEqual({ complete: '', rest: 'a@x' });
    expect(splitDraft('')).toEqual({ complete: '', rest: '' });
  });
});

describe('pastedValue', () => {
  it('replaces the selection with the pasted text', () => {
    expect(pastedValue('ab', 1, 1, 'X')).toBe('aXb');
    expect(pastedValue('abcd', 1, 3, 'X')).toBe('aXd');
  });

  it('appends without a selection and clamps the bounds', () => {
    expect(pastedValue('ab', null, null, 'X')).toBe('abX');
    expect(pastedValue('ab', 5, 9, 'X')).toBe('abX');
    expect(pastedValue('ab', 2, 0, 'X')).toBe('abX');
    expect(pastedValue('ab', -1, 1, 'X')).toBe('Xb');
  });
});

describe('recipientKeyAction', () => {
  it('commits a non-empty draft on Enter, else lets the form submit', () => {
    expect(recipientKeyAction('Enter', 'a@x.example', 0)).toBe('commit');
    expect(recipientKeyAction('Enter', '  ', 2)).toBe('none');
    expect(recipientKeyAction('Enter', '', 2)).toBe('none');
  });

  it('moves to the last chip on Backspace in an empty input', () => {
    expect(recipientKeyAction('Backspace', '', 2)).toBe('focus-last');
    expect(recipientKeyAction('Backspace', '', 0)).toBe('none');
    expect(recipientKeyAction('Backspace', 'a', 2)).toBe('none');
    expect(recipientKeyAction('a', '', 2)).toBe('none');
  });
});

describe('removesChip', () => {
  it('removes a chip on Backspace and Delete only', () => {
    expect(removesChip('Backspace')).toBe(true);
    expect(removesChip('Delete')).toBe(true);
    expect(removesChip('Enter')).toBe(false);
  });
});

describe('commitFeedback', () => {
  const valid = (address: string) => address.includes('@');

  it('announces the added addresses, then the invalid ones among them', () => {
    expect(commitFeedback({ added: ['a@x.example', 'oops'], duplicates: [] }, valid)).toEqual({
      notice: undefined,
      announcements: [
        { key: 'components.recipientInput.added', params: { count: 2, addresses: 'a@x.example, oops' } },
        { key: 'components.recipientInput.invalidAdded', params: { count: 1, addresses: 'oops' } },
      ],
    });
  });

  it('shows and announces the duplicates left out, after the additions', () => {
    const notice = {
      key: 'components.recipientInput.duplicates',
      params: { count: 1, addresses: 'A@x.example' },
    };
    expect(commitFeedback({ added: ['b@x.example'], duplicates: ['A@x.example'] }, valid)).toEqual({
      notice,
      announcements: [
        { key: 'components.recipientInput.added', params: { count: 1, addresses: 'b@x.example' } },
        notice,
      ],
    });
  });

  it('announces only the notice when every address was already there', () => {
    const feedback = commitFeedback({ added: [], duplicates: ['a@x.example', 'b@x.example'] }, valid);
    expect(feedback.notice?.params).toEqual({ count: 2, addresses: 'a@x.example, b@x.example' });
    expect(feedback.announcements).toEqual([feedback.notice]);
  });

  it('says nothing when the commit changed nothing', () => {
    expect(commitFeedback({ added: [], duplicates: [] }, valid)).toEqual({
      notice: undefined,
      announcements: [],
    });
  });
});

describe('commitsLeftDraft', () => {
  it('commits a draft left in the input once the focus is elsewhere', () => {
    expect(commitsLeftDraft('bob@example.org', false)).toBe(true);
  });

  it('keeps a blank draft, or the draft of an input focused again', () => {
    expect(commitsLeftDraft('  ', false)).toBe(false);
    expect(commitsLeftDraft('', false)).toBe(false);
    expect(commitsLeftDraft('bob@example.org', true)).toBe(false);
  });
});
