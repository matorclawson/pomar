const {readFileSync} = require('node:fs');
const {join} = require('node:path');
const {test} = require('node:test');
const assert = require('node:assert/strict');
const yaml = readFileSync(join(__dirname, 'review-head.yml'), 'utf8');
const script = yaml.split('          script: |\n')[1].split('\n').map(x => x.slice(12)).join('\n');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const evaluate = new AsyncFunction('github', 'context', 'core', 'process', script);
const head = 'a'.repeat(40), other = 'b'.repeat(40);
const review = (id, verdict = 'no-blocker', sha = head, seat = 'POMAR-CC', login = 'review-publisher') => ({
  id, user: {login}, updated_at: `2026-01-01T00:00:${String(id).padStart(2, '0')}Z`,
  body: `Reviewing-Seat: ${seat}\nReviewed-Head: ${sha}\nReview-Verdict: ${verdict}`,
});
async function run({publisher = 'review-publisher', comments = [review(1)], body = 'Implementation-Seat: POMAR-Codex', payload = {}, statuses = [], changed = false} = {}) {
  let reads = 0, failure; const writes = [];
  const github = {rest: {pulls: {get: async () => ({data: {state: 'open', head: {sha: changed && ++reads > 1 ? other : head}, body}})},
    issues: {listComments: 'comments'}, repos: {listCommitStatusesForRef: 'statuses', createCommitStatus: async value => writes.push(value)}},
    paginate: async method => method === 'comments' ? comments : statuses};
  const context = {repo: {owner: 'example', repo: 'project'}, payload: {pull_request: {number: 1}, ...payload}, serverUrl: 'https://github.com', runId: 1};
  await evaluate(github, context, {info() {}, setFailed(message) {failure = message;}}, {env: {REVIEW_PUBLISHER: publisher}});
  return {writes, failure};
}
for (const [name, options, expected] of [
  ['current exact head', {}, 'success'],
  ['stale head', {comments: [review(1, 'no-blocker', other)]}, 'failure'],
  ['new blocked supersedes old approval', {comments: [review(1), review(2, 'blocked')]}, 'failure'],
  ['new stale supersedes old approval', {comments: [review(1), review(2, 'no-blocker', other)]}, 'failure'],
  ['missing publisher configuration', {publisher: ''}, 'failure'],
  ['invalid publisher configuration', {publisher: 'not a login'}, 'failure'],
  ['missing review', {comments: []}, 'failure'],
  ['missing implementation seat', {body: ''}, 'failure'],
  ['duplicate implementation seat', {body: 'Implementation-Seat: POMAR-Codex\nImplementation-Seat: POMAR-CC'}, 'failure'],
  ['same seat cannot review itself', {comments: [review(1, 'no-blocker', head, 'POMAR-Codex')]}, 'failure'],
  ['unknown publisher', {comments: [review(1, 'no-blocker', head, 'POMAR-CC', 'outsider')]}, 'failure'],
  ['malformed verdict', {comments: [review(1, 'approve')]}, 'failure'],
  ['duplicate head in latest review', {comments: [{...review(1), body: review(1).body + '\nReviewed-Head: ' + head}]}, 'failure'],
  ['review inside code fence does not count', {comments: [{...review(1), body: '```text\n' + review(1).body + '\n```'}]}, 'failure'],
  ['blockquote does not count', {comments: [{...review(1), body: review(1).body.split('\n').map(x => '> ' + x).join('\n')}]}, 'failure'],
  ['review withdrawal holds', {payload: {action: 'deleted', comment: review(2)}}, 'failure'],
  ['withdrawal remains held on another event', {statuses: [{context: 'review-head', description: 'Review withdrawn at 2026-01-01T00:00:02Z'}]}, 'failure'],
  ['new explicit review clears withdrawal', {comments: [review(3)], statuses: [{context: 'review-head', description: 'Review withdrawn at 2026-01-01T00:00:02Z'}]}, 'success'],
  ['reverse seat direction', {body: 'Implementation-Seat: POMAR-CC', comments: [review(1, 'no-blocker', head, 'POMAR-Codex')]}, 'success'],
]) test(name, async () => {
  const r = await run(options);
  assert.equal(r.writes.length, 1);
  assert.equal(r.writes[0].state, expected);
  assert.equal(r.writes[0].sha, head);
  assert.equal(r.writes[0].context, 'review-head');
  assert.equal(Boolean(r.failure), expected !== 'success');
});
test('changed PR head never receives success', async () => {
  await assert.rejects(run({changed: true}), /changed while evaluating/);
});
test('policy executes no PR code and dependency is immutable', () => {
  assert.match(yaml, /github-script@[a-f0-9]{40}/);
  assert.doesNotMatch(yaml, /actions\/checkout|secrets\.|eval\(/);
});
