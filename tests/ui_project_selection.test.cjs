const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const source = html.slice(html.indexOf('    function savedProjectId()'), html.indexOf('    function proxyHostLabel('));
const projects = [
  { id: 1, name: 'Atlas', updated_at: '2026-01-01T00:00:00Z' },
  { id: 2, name: 'Birch', updated_at: '2026-01-03T00:00:00.123456789Z' },
  { id: 3, name: 'Cedar', updated_at: '2026-01-03T00:00:00.123400000Z' },
];

function fixture({ hint = null, query = '', saved = null, redirected = false, list = projects } = {}) {
  const select = { innerHTML: '', value: '' };
  const state = { projectId: null };
  let stored = saved;
  let changes = 0;
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const context = vm.createContext({
    state, URL, URLSearchParams,
    location: { origin: 'http://localhost', search: query },
    localStorage: {
      getItem: () => stored,
      setItem: (_, value) => { stored = value; },
      removeItem: () => { stored = null; },
    },
    $: () => select,
    escapeHtml: String,
    projectChanged: async () => { changes++; },
    api: async (_, __, onResponse) => {
      await pending;
      onResponse({
        redirected,
        url: redirected ? 'http://localhost/other' : 'http://localhost/api/v1/projects',
        headers: { get: () => hint },
      });
      return { projects: list };
    },
  });
  const { loadProjects } = vm.runInContext(`${source}; ({ loadProjects })`, context);
  return { state, select, loadProjects, release, get changes() { return changes; }, get stored() { return stored; } };
}

test('initial selection respects trusted hint, deep link, saved selection, and latest update', async () => {
  for (const [options, expected] of [
    [{ hint: '1', query: '?project=2', saved: '3' }, 1],
    [{ hint: '999', query: '?project=2', saved: '3' }, 2],
    [{ hint: 'invalid', query: '?project=999', saved: '3' }, 3],
    [{ query: '?project=1.0', saved: '3' }, 3],
    [{ query: '?project=999' }, 2],
    [{ hint: '1', query: '?project=2', saved: '3', redirected: true }, 2],
    [{ list: [], query: '?project=2', saved: '3' }, null],
  ]) {
    const app = fixture(options);
    const loading = app.loadProjects(null, true);
    assert.equal(app.state.projectId, null);
    assert.equal(app.changes, 0);
    app.release();
    await loading;
    assert.equal(app.state.projectId, expected);
    assert.equal(app.select.value, expected ? String(expected) : '');
    assert.equal(app.stored, expected ? String(expected) : null);
    assert.equal(app.changes, 1);
  }
});

test('refresh preserves the current or explicitly requested selection', async () => {
  const app = fixture({ hint: '1', saved: '3' });
  app.release();
  app.state.projectId = 2;
  await app.loadProjects();
  assert.equal(app.state.projectId, 2);
  await app.loadProjects(3);
  assert.equal(app.state.projectId, 3);
});

const helpers = vm.runInContext(
  `${html.slice(html.indexOf('    // --- pure helpers'), html.indexOf('    // --- end pure helpers ---'))}
   ({ fuzzPayloadSummary, mergeHistoryPage, mergeWebSocketMessages })`,
  vm.createContext({}),
);

test('fuzz payloads render as a readable summary', () => {
  assert.equal(helpers.fuzzPayloadSummary([]), '—');
  assert.equal(helpers.fuzzPayloadSummary(undefined), '—');
  assert.equal(
    helpers.fuzzPayloadSummary([
      { insertion_point: 'id', location: 'url', encoding: 'text', value: "1' OR 1=1" },
      { insertion_point: 'blob', location: 'body', encoding: 'base64', value: '/w==' },
    ]),
    "id=1' OR 1=1, blob=[base64] /w==",
  );
});

test('history refresh keeps loaded pages and replaces on a gap', () => {
  const item = id => ({ exchange_id: id });
  const ids = items => items.map(i => i.exchange_id);
  const loaded = [5, 4, 3, 2, 1].map(item);
  const grown = helpers.mergeHistoryPage(loaded, [7, 6, 5, 4].map(item));
  assert.deepEqual(ids(grown.items), [7, 6, 5, 4, 3, 2, 1]);
  assert.equal(grown.replaced, false);
  const gap = helpers.mergeHistoryPage(loaded, [20, 19, 18].map(item));
  assert.deepEqual(ids(gap.items), [20, 19, 18]);
  assert.equal(gap.replaced, true);
  assert.equal(helpers.mergeHistoryPage([], [2, 1].map(item)).replaced, true);
});

test('websocket messages append newer ones and keep only the newest', () => {
  const message = id => ({ id });
  const ids = items => items.map(m => m.id);
  const held = [1, 2, 3].map(message);
  assert.deepEqual(ids(helpers.mergeWebSocketMessages(held, [3, 4, 5].map(message), 10)), [1, 2, 3, 4, 5]);
  assert.deepEqual(ids(helpers.mergeWebSocketMessages(held, [4, 5, 6].map(message), 4)), [3, 4, 5, 6]);
});
