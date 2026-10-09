const {readFileSync} = require('node:fs');
const {join} = require('node:path');
const {test} = require('node:test');
const assert = require('node:assert/strict');
const yaml = readFileSync(join(__dirname, 'review-head.yml'), 'utf8');
const script = yaml.split('          script: |\n')[1].split('\n').map(x => x.slice(12)).join('\n');
const evaluate = new (Object.getPrototypeOf(async function () {}).constructor)('github', 'context', 'core', 'process', script);
const head = 'a'.repeat(40), other = 'b'.repeat(40);
const review = (id, verdict = 'no-blocker', sha = head, seat = 'POMAR-CC') => ({id, user: {login: 'review-publisher'},
  created_at: `2026-01-01T00:00:${String(id).padStart(2, '0')}Z`, updated_at: `2026-01-01T00:00:${String(id).padStart(2, '0')}Z`,
  body: `Reviewing-Seat: ${seat}\nReviewed-Head: ${sha}\nReview-Verdict: ${verdict}`});
const edit = (c, body = c.body) => ({...c, updated_at: '2026-01-02T00:00:00Z', body});
async function run({publisher = 'review-publisher', comments = [review(1)], body = 'Implementation-Seat: POMAR-Codex',
  ref = 'pomar-codex/implementation', state = 'open', payload = {}, snapshots, changed, failList = 0, failPending = false} = {}) {
  let reads = 0, lists = 0, failure; const writes = [];
  const github = {rest: {pulls: {get: async () => {
    reads++; return {data: {state, head: {sha: changed === 'head' && reads > 1 ? other : head, ref},
      body: changed === 'body' && reads > 1 ? body + '\nchanged' : body}};
  }}, issues: {listComments: 'comments'}, repos: {createCommitStatus: async value => {
    if (failPending && value.state === 'pending') throw new Error('pending API failed'); writes.push(value);
  }}}, paginate: async (method, args) => {
    assert.equal(method, 'comments'); assert.equal(args.per_page, 100); lists++;
    assert.equal(writes[0]?.state, 'pending', 'pending precedes any review read');
    if (lists === failList) throw new Error('comment API failed');
    return snapshots ? snapshots[Math.min(lists - 1, snapshots.length - 1)] : comments;
  }};
  try {
    await evaluate(github, {repo: {owner: 'example', repo: 'project'}, payload: {pull_request: {number: 1}, ...payload},
      serverUrl: 'https://github.com', runId: 1}, {info() {}, setFailed(message) {failure = message;}}, {env: {REVIEW_PUBLISHER: publisher}});
    return {writes, failure};
  } catch (error) {return {writes, error};}
}
for (const [name, options, expected] of [
  ['current exact head', {}, 'success'],
  ['stale head', {comments: [review(1, 'no-blocker', other)]}, 'failure'],
  ['new blocked overrides old approval', {comments: [review(1), review(2, 'blocked')]}, 'failure'],
  ['editing old approval cannot overtake newer blocker', {comments: [edit(review(1)), review(2, 'blocked')]}, 'failure'],
  ['editing old approval onto new head is void', {comments: [edit(review(1, 'no-blocker', head))]}, 'failure'],
  ['removing latest review seat cannot revive old approval', {comments: [review(1), edit(review(2, 'blocked'), 'Reviewed-Head: ' + head)]}, 'failure'],
  ['removing ALL latest review markers cannot revive old approval', {comments: [review(1), edit(review(2), 'no markers remain')]}, 'failure'],
  ['fresh explicit review resolves an edited declaration', {comments: [review(1), edit(review(2)), review(3)]}, 'success'],
  ['unrelated unedited comment does not replace review', {comments: [review(1), {...review(2), body: 'progress only'}]}, 'success'],
  ['unrelated edited comment conservatively holds', {comments: [review(1), edit(review(2), 'progress only')]}, 'failure'],
  ['missing publisher', {publisher: ''}, 'failure'],
  ['invalid publisher', {publisher: 'not a login'}, 'failure'],
  ['missing review', {comments: []}, 'failure'],
  ['missing implementation seat', {body: ''}, 'failure'],
  ['duplicate implementation seat', {body: 'Implementation-Seat: POMAR-Codex\nImplementation-Seat: POMAR-CC'}, 'failure'],
  ['body edit cannot change fixed branch seat', {body: 'Implementation-Seat: POMAR-CC', comments: [review(1, 'no-blocker', head, 'POMAR-Codex')]}, 'failure'],
  ['unknown branch prefix refuses', {ref: 'dev/old-branch'}, 'failure'],
  ['same seat cannot review itself', {comments: [review(1, 'no-blocker', head, 'POMAR-Codex')]}, 'failure'],
  ['unknown publisher', {comments: [{...review(1), user: {login: 'outsider'}}]}, 'failure'],
  ['malformed verdict', {comments: [review(1, 'approve')]}, 'failure'],
  ['new malformed review overrides old approval', {comments: [review(1), {...review(2), body: 'Reviewing-Seat: ???'}]}, 'failure'],
  ['duplicate latest head', {comments: [{...review(1), body: review(1).body + '\nReviewed-Head: ' + head}]}, 'failure'],
  ['uppercase head refuses', {comments: [review(1, 'no-blocker', head.toUpperCase())]}, 'failure'],
  ['backtick fence ignores declaration', {comments: [{...review(1), body: '```text\n' + review(1).body + '\n```'}]}, 'failure'],
  ['tilde fence ignores declaration', {comments: [{...review(1), body: '~~~text\n' + review(1).body + '\n~~~'}]}, 'failure'],
  ['quoted declaration ignored', {comments: [{...review(1), body: review(1).body.split('\n').map(x => '> ' + x).join('\n')}]}, 'failure'],
  ['HTML comment ignored', {comments: [{...review(1), body: '<!--\n' + review(1).body + '\n-->'}]}, 'failure'],
  ['collapsed details ignored', {comments: [{...review(1), body: '<details>\n' + review(1).body + '\n</details>'}]}, 'failure'],
  ['creation id breaks equal-time ties', {comments: [review(1), {...review(2, 'blocked'), created_at: review(1).created_at, updated_at: review(1).created_at}]}, 'failure'],
  ['deletion is not withdrawal: explicit blocker remains authoritative', {payload: {action: 'deleted', comment: review(3)}, comments: [review(1), review(2, 'blocked')]}, 'failure'],
  ['deletion does not invent a tombstone: new blocked comment required', {payload: {action: 'deleted', comment: review(2, 'blocked')}}, 'success'],
  ['closed PR cannot preserve success', {state: 'closed'}, 'failure'],
  ['reopened PR re-evaluates durable blocker', {payload: {action: 'reopened'}, comments: [review(1), review(2, 'blocked')]}, 'failure'],
  ['reverse seat direction', {ref: 'pomar-cc/implementation', body: 'Implementation-Seat: POMAR-CC', comments: [review(1, 'no-blocker', head, 'POMAR-Codex')]}, 'success'],
  ['paginated complete snapshot includes later blocker', {comments: [...Array.from({length: 101}, (_, i) => ({...review(i), body: 'progress'})), review(50, 'blocked')]}, 'failure'],
]) test(name, async () => {
  const r = await run(options); assert.ifError(r.error);
  assert.deepEqual(r.writes.map(x => x.state), ['pending', expected]);
  assert.ok(r.writes.every(x => x.sha === head && x.context === 'review-head'));
  assert.equal(Boolean(r.failure), expected !== 'success');
});
for (const [name, options] of [
  ['head changes after snapshot', {changed: 'head'}],
  ['body changes after snapshot', {changed: 'body'}],
  ['blocker arrives before second review read', {snapshots: [[review(1)], [review(1), review(2, 'blocked')]]}],
  ['blocker arrives during final PR read', {snapshots: [[review(1)], [review(1)], [review(1), review(2, 'blocked')]]}],
  ['latest declaration edited during evaluation', {snapshots: [[review(1)], [edit(review(1))]]}],
  ['review API fails with an earlier success', {failList: 1}],
  ['final review API fails', {failList: 3}],
]) test(name + ' leaves pending, never final success', async () => {
  const r = await run(options); assert.ok(r.error); assert.deepEqual(r.writes.map(x => x.state), ['pending']);
});
test('pending write failure is reported; no false atomic claim', async () => {
  const r = await run({failPending: true}); assert.match(r.error.message, /pending API failed/); assert.deepEqual(r.writes, []);
});
test('trusted base only, dependency immutable, runs not cancelled', () => {
  assert.match(yaml, /github-script@[a-f0-9]{40}/); assert.match(yaml, /cancel-in-progress: false/);
  assert.doesNotMatch(yaml, /actions\/checkout|secrets\.|eval\(/);
});

for (const raw of [' 12', '012', '12 ', '12\n', '12\t', '+12', '1e1', '12.0', '0', '9007199254740993', 12]) {
  test(`noncanonical dispatch ${JSON.stringify(raw)} refuses before status writes`, async () => {
    const r = await run({payload: {pull_request: null, inputs: {pull_request: raw}}});
    assert.match(r.error.message, /canonical decimal/); assert.deepEqual(r.writes, []);
  });
}
test('canonical dispatch shares the exact PR number and evaluates normally', async () => {
  const r = await run({payload: {pull_request: null, inputs: {pull_request: '12'}}});
  assert.ifError(r.error); assert.deepEqual(r.writes.map(x => x.state), ['pending', 'success']);
});
