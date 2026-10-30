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
